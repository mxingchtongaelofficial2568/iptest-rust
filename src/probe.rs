use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Instant,
};

use anyhow::{Context, Result, anyhow};
use bytes::{BufMut, BytesMut};
use maxminddb::Reader;
use memchr::memmem;
use rustls_pki_types::ServerName;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;

use crate::{
    model::{IpEntry, Location, Opts, ProbeResult, TargetUrl},
    runtime::{
        CONNECT_TIMEOUT, HEADER_BUFFER_LIMIT, SPEED_TIMEOUT, TRACE_HOST, TRACE_READ_LIMIT,
        TRACE_TIMEOUT,
    },
};

pub async fn probe_ip(
    entry: IpEntry,
    opts: &Opts,
    location_map: &HashMap<String, Location>,
    asn_db: Option<&Arc<Reader<Vec<u8>>>>,
    tls_connector: &TlsConnector,
) -> Option<ProbeResult> {
    let address = parse_socket_addr(&entry.ip, entry.port).ok()?;
    let start = Instant::now();
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await.ok()?.ok()?;
    let _ = stream.set_nodelay(true);
    let tcp_duration = start.elapsed();

    if opts.delay > 0 && tcp_duration.as_millis() > u128::from(opts.delay) {
        return None;
    }

    let response = timeout(TRACE_TIMEOUT, async {
        if opts.tls {
            let server_name = ServerName::try_from(TRACE_HOST).ok()?;
            let mut tls_stream = tls_connector.connect(server_name, stream).await.ok()?;
            write_and_read_limited(&mut tls_stream, TRACE_REQUEST, TRACE_READ_LIMIT)
                .await
                .ok()
        } else {
            let mut plain = stream;
            write_and_read_limited(&mut plain, TRACE_REQUEST, TRACE_READ_LIMIT)
                .await
                .ok()
        }
    })
    .await
    .ok()??;

    let body = extract_http_body(&response);
    let body_text = String::from_utf8_lossy(body);
    if !body_text.contains("uag=Mozilla/5.0") {
        return None;
    }

    let response_data = parse_trace_response(&body_text);
    let data_center = response_data.get("colo")?.to_string();
    let loc_code = response_data.get("loc")?.to_string();
    let field = |k: &str| response_data.get(k).map(|v| v.to_string()).unwrap_or_default();
    let outbound_ip = response_data.get("ip").copied().unwrap_or("");
    let ip_type = get_ip_type(outbound_ip).to_string();
    let location = location_map.get(&data_center);

    let (asn_number, asn_org) = lookup_asn(asn_db, outbound_ip);

    Some(ProbeResult {
        ip: entry.ip,
        port: entry.port,
        data_center,
        loc_code,
        region: location.map(|l| l.region.clone()).unwrap_or_default(),
        city: location.map(|l| l.city.clone()).unwrap_or_default(),
        region_zh: location.map(|l| l.region_zh.clone()).unwrap_or_default(),
        country: location.map(|l| l.country.clone()).unwrap_or_default(),
        city_zh: location.map(|l| l.city_zh.clone()).unwrap_or_default(),
        emoji: location.map(|l| l.emoji.clone()).unwrap_or_default(),
        latency_ms: tcp_duration.as_millis(),
        tcp_duration,
        outbound_ip: outbound_ip.to_string(),
        ip_type,
        visit_scheme: field("visit_scheme"),
        tls_version: field("tls"),
        sni: field("sni"),
        http_version: field("http"),
        warp: field("warp"),
        gateway: field("gateway"),
        rbi: field("rbi"),
        kex: field("kex"),
        timestamp: field("ts"),
        autonomous_system_number: asn_number,
        autonomous_system_organization: asn_org,
        download_speed: None,
    })
}

pub async fn speed_test_ip(
    ip: &str,
    port: u16,
    target: &TargetUrl,
    enable_tls: bool,
    tls_connector: &TlsConnector,
) -> f64 {
    let address = match parse_socket_addr(ip, port) {
        Ok(addr) => addr,
        Err(_) => return 0.0,
    };

    let start = Instant::now();
    let stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => stream,
        _ => return 0.0,
    };
    let _ = stream.set_nodelay(true);

    let downloaded = if enable_tls {
        let server_name = match ServerName::try_from(target.host.clone()) {
            Ok(name) => name,
            Err(_) => return 0.0,
        };
        let mut tls_stream = match timeout(SPEED_TIMEOUT, tls_connector.connect(server_name, stream)).await {
            Ok(Ok(stream)) => stream,
            _ => return 0.0,
        };
        count_http_body_bytes(&mut tls_stream, &target.speed_request[..], SPEED_TIMEOUT)
            .await
            .unwrap_or(0)
    } else {
        let mut plain = stream;
        count_http_body_bytes(&mut plain, &target.speed_request[..], SPEED_TIMEOUT)
            .await
            .unwrap_or(0)
    };

    let elapsed = start.elapsed().as_secs_f64().max(0.001);
    downloaded as f64 / elapsed / 1024.0
}

pub fn build_target_url(raw: &str, enable_tls: bool) -> Result<TargetUrl> {
    let full = if raw.contains("://") {
        raw.to_string()
    } else if enable_tls {
        format!("https://{}", raw)
    } else {
        format!("http://{}", raw)
    };

    let url = reqwest::Url::parse(&full).with_context(|| format!("测速地址无效: {full}"))?;
    let host = url
        .host_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("测速地址缺少主机名"))?;
    let mut path = url.path().to_string();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    if path.is_empty() {
        path = "/".to_string();
    }

    let referer_raw = format!("https://{host}/");
    let mut req = BytesMut::with_capacity(256 + path.len() + host.len() + referer_raw.len());
    req.put_slice(b"GET ");
    req.put_slice(path.as_bytes());
    req.put_slice(b" HTTP/1.1\r\nHost: ");
    req.put_slice(host.as_bytes());
    req.put_slice(b"\r\nUser-Agent: Mozilla/5.0\r\nReferer: ");
    req.put_slice(referer_raw.as_bytes());
    req.put_slice(b"\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");

    Ok(TargetUrl {
        host,
        path_and_query: path,
        referer: Some(referer_raw),
        speed_request: req.to_vec(),
    })
}

const TRACE_REQUEST: &[u8] = b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";

async fn write_and_read_limited<T>(stream: &mut T, request: &[u8], limit: usize) -> Result<Vec<u8>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request).await.context("发送请求失败")?;
    stream.flush().await.context("刷新请求失败")?;

    let mut data = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await.context("读取响应失败")?;
        if n == 0 {
            break;
        }
        if data.len() + n > limit {
            return Err(anyhow!("响应超过限制大小"));
        }
        data.extend_from_slice(&buf[..n]);
    }
    Ok(data)
}

async fn count_http_body_bytes<T>(stream: &mut T, request: &[u8], max_duration: std::time::Duration) -> Result<usize>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request).await.context("发送测速请求失败")?;
    stream.flush().await.context("刷新测速请求失败")?;

    let started = Instant::now();
    let mut total = 0usize;
    let mut headers_done = false;
    let mut header_buf = Vec::with_capacity(8192);
    let mut buf = [0u8; 16 * 1024];

    loop {
        let elapsed = started.elapsed();
        if elapsed >= max_duration {
            break;
        }

        let remain = max_duration - elapsed;
        let n = match timeout(remain, stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(err)) => return Err(err).context("读取测速响应失败"),
            Err(_) => break,
        };
        if n == 0 {
            break;
        }

        if headers_done {
            total += n;
            continue;
        }

        header_buf.extend_from_slice(&buf[..n]);
        if let Some(pos) = memmem::find(&header_buf, b"\r\n\r\n") {
            let body_start = pos + 4;
            if header_buf.len() > body_start {
                total += header_buf.len() - body_start;
            }
            headers_done = true;
        } else if header_buf.len() > HEADER_BUFFER_LIMIT {
            return Err(anyhow!("HTTP 响应头过大"));
        }
    }

    Ok(total)
}

fn extract_http_body(response: &[u8]) -> &[u8] {
    memmem::find(response, b"\r\n\r\n")
        .map(|pos| &response[pos + 4..])
        .unwrap_or(response)
}

fn parse_trace_response<'a>(body: &'a str) -> HashMap<&'a str, &'a str> {
    body.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            let (key, value) = trimmed.split_once('=')?;
            Some((key.trim(), value.trim()))
        })
        .collect()
}

fn lookup_asn(asn_db: Option<&Arc<Reader<Vec<u8>>>>, outbound_ip: &str) -> (u32, String) {
    let Some(db) = asn_db else {
        return (0, String::new());
    };
    let Ok(ip) = IpAddr::from_str(outbound_ip) else {
        return (0, String::new());
    };

    match db.lookup::<maxminddb::geoip2::Asn<'_>>(ip) {
        Ok(asn) => (
            asn.autonomous_system_number.unwrap_or(0),
            asn.autonomous_system_organization
                .unwrap_or_default()
                .to_string(),
        ),
        Err(_) => (0, String::new()),
    }
}

fn get_ip_type(ip: &str) -> &'static str {
    if ip.is_empty() {
        return "未知";
    }
    match IpAddr::from_str(ip) {
        Ok(IpAddr::V4(_)) => "IPv4",
        Ok(IpAddr::V6(_)) => "IPv6",
        Err(_) => "无效IP",
    }
}

fn parse_socket_addr(ip: &str, port: u16) -> Result<SocketAddr> {
    let ip_addr = IpAddr::from_str(ip).with_context(|| format!("无效 IP: {ip}"))?;
    Ok(SocketAddr::new(ip_addr, port))
}
