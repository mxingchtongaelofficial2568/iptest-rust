use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request as HyperRequest, client::conn::http1};
use hyper_util::rt::TokioIo;
use maxminddb::Reader;
use rustls_pki_types::ServerName;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::timeout,
};
use tokio_rustls::TlsConnector;

use crate::{
    model::{IpEntry, Location, Opts, ProbeResult, TargetUrl},
    runtime::{
        CONNECT_TIMEOUT, SPEED_TIMEOUT, TLS_HANDSHAKE_TIMEOUT,
        TRACE_HOST, TRACE_TIMEOUT,
    },
};

const LATENCY_SAMPLES: u32 = 3;
const SOCKET_BUFFER_SIZE: u32 = 4 * 1024 * 1024;

pub async fn probe_ip(
    entry: IpEntry,
    opts: &Opts,
    location_map: &HashMap<String, Location>,
    asn_db: Option<&Arc<Reader<Vec<u8>>>>,
    tls_connector: &TlsConnector,
) -> Option<ProbeResult> {
    let address = parse_socket_addr(&entry.ip, entry.port).ok()?;

    // Fix 8: stagger connections to reduce epoll/IOCP pressure under high concurrency
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    entry.ip.hash(&mut hasher);
    let stagger_ms = (hasher.finish() % 10) as u64;
    tokio::time::sleep(std::time::Duration::from_millis(stagger_ms)).await;

    // Fix 7: multiple samples to get minimum latency, avoiding scheduler jitter,
    // ARP cache miss on first connect, and SYN retransmit outliers
    let mut best_duration = std::time::Duration::MAX;
    let mut best_stream = None;

    for _ in 0..LATENCY_SAMPLES {
        let socket = match create_socket(&address) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let start = Instant::now();
        match timeout(CONNECT_TIMEOUT, socket.connect(address)).await {
            Ok(Ok(stream)) => {
                let dur = start.elapsed();
                if dur < best_duration {
                    best_duration = dur;
                    let _ = stream.set_nodelay(true);
                    best_stream = Some(stream);
                }
            }
            _ => continue,
        }
    }

    let stream = best_stream?;
    let tcp_duration = best_duration;

    if opts.delay > 0 && tcp_duration.as_millis() > u128::from(opts.delay) {
        return None;
    }

    let body_text = timeout(TRACE_TIMEOUT, async {
        if opts.tls {
            let server_name = ServerName::try_from(TRACE_HOST).ok()?;
            let tls_stream = tls_connector.connect(server_name, stream).await.ok()?;
            hyper_trace(TokioIo::new(tls_stream), opts.tls).await
        } else {
            hyper_trace(TokioIo::new(stream), opts.tls).await
        }
    })
    .await
    .ok()
    .flatten()
    .unwrap_or_default();

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
        name: entry.name,
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

    let socket = match create_socket(&address) {
        Ok(s) => s,
        Err(_) => return 0.0,
    };
    let stream = match timeout(CONNECT_TIMEOUT, socket.connect(address)).await {
        Ok(Ok(stream)) => stream,
        _ => return 0.0,
    };
    let _ = stream.set_nodelay(true);

    let (downloaded, elapsed) = if enable_tls {
        let server_name = match ServerName::try_from(target.host.clone()) {
            Ok(name) => name,
            Err(_) => return 0.0,
        };
        let tls_stream = match timeout(TLS_HANDSHAKE_TIMEOUT, tls_connector.connect(server_name, stream)).await {
            Ok(Ok(stream)) => stream,
            _ => return 0.0,
        };
        hyper_speed_test(TokioIo::new(tls_stream), target, "https", SPEED_TIMEOUT).await
    } else {
        hyper_speed_test(TokioIo::new(stream), target, "http", SPEED_TIMEOUT).await
    };

    let elapsed_secs = elapsed.as_secs_f64().max(0.001);
    downloaded as f64 / elapsed_secs / 1024.0
}

async fn hyper_speed_test<T>(io: TokioIo<T>, target: &TargetUrl, scheme: &str, max_duration: Duration) -> (usize, Duration)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = match timeout(max_duration, http1::handshake(io)).await {
        Ok(Ok(pair)) => pair,
        _ => return (0, Duration::ZERO),
    };

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let uri = format!("{}://{}{}", scheme, target.host, target.path_and_query);
    let mut builder = HyperRequest::builder()
        .method("GET")
        .uri(&uri)
        .header("Host", &target.host)
        .header("User-Agent", "Mozilla/5.0")
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close");
    if let Some(ref referer) = target.referer {
        builder = builder.header("Referer", referer.as_str());
    }
    let request = match builder.body(Full::new(Bytes::new())) {
        Ok(req) => req,
        Err(_) => return (0, Duration::ZERO),
    };

    let start = Instant::now();

    let resp = match timeout(max_duration, sender.send_request(request)).await {
        Ok(Ok(resp)) => resp,
        _ => return (0, start.elapsed()),
    };

    let mut body = resp.into_body();
    let mut total = 0usize;
    let deadline = start + max_duration;

    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remain = deadline - now;
        match timeout(remain, body.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    total += data.len();
                }
            }
            _ => break,
        }
    }

    (total, start.elapsed())
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

    Ok(TargetUrl {
        host,
        path_and_query: path,
        referer: Some(referer_raw),
    })
}

// Fix 9: create a TcpSocket with configured buffer sizes for high BDP links
fn create_socket(addr: &SocketAddr) -> std::io::Result<tokio::net::TcpSocket> {
    let socket = match addr {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    let _ = socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE);
    let _ = socket.set_send_buffer_size(SOCKET_BUFFER_SIZE);
    Ok(socket)
}

async fn hyper_trace<T>(io: TokioIo<T>, enable_tls: bool) -> Option<String>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = http1::handshake(io).await.ok()?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let scheme = if enable_tls { "https" } else { "http" };
    let uri = format!("{}://{}/cdn-cgi/trace", scheme, crate::runtime::TRACE_HOST);

    let request = HyperRequest::builder()
        .method("GET")
        .uri(&uri)
        .header("Host", crate::runtime::TRACE_HOST)
        .header("User-Agent", "Mozilla/5.0")
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .body(Full::new(Bytes::new()))
        .ok()?;

    let resp = sender.send_request(request).await.ok()?;

    let body = resp.into_body().collect().await.ok()?;
    String::from_utf8(body.to_bytes().to_vec()).ok()
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
