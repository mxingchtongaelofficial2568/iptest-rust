use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use indicatif::{ProgressBar, ProgressStyle};
use maxminddb::Reader;
use owo_colors::OwoColorize;
use reqwest::Client;
use rustls::{ClientConfig, RootCertStore};
use tokio::fs;
use tokio_rustls::TlsConnector;

use crate::model::{IpEntry, Location};

pub const TRACE_HOST: &str = "speed.cloudflare.com";
pub const TRACE_PATH: &str = "/cdn-cgi/trace";
pub const LOCATIONS_URL: &str = "https://locations-adw.pages.dev/";
pub const ASN_DB_URL: &str = "https://jsd.onmicrosoft.cn/gh/seketiti/GeoLiet2@release/GeoLite2-ASN.mmdb";
pub const LOCATIONS_FILE: &str = "locations.json";
pub const LEGACY_LOCATION_FILE: &str = "location.json";
pub const ASN_DB_FILE: &str = "GeoLite2-ASN.mmdb";
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
pub const TRACE_TIMEOUT: Duration = Duration::from_secs(2);
pub const SPEED_TIMEOUT: Duration = Duration::from_secs(5);
pub const TRACE_READ_LIMIT: usize = 32 * 1024;
pub const HEADER_BUFFER_LIMIT: usize = 64 * 1024;

pub fn normalize_args<I>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    args.into_iter()
        .enumerate()
        .map(|(idx, arg)| {
            if idx == 0 || arg.starts_with("--") || arg == "-h" || arg == "-V" {
                arg
            } else if arg.starts_with('-') && arg.len() > 2 {
                format!("--{}", &arg[1..])
            } else {
                arg
            }
        })
        .collect()
}

pub fn runtime_base_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("无法获取当前二进制路径")?;
    exe.parent()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("无法确定二进制所在目录"))
}

pub fn resolve_runtime_path(base_dir: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

pub fn spinner(message: impl Into<String>) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(120));
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ "),
    );
    pb.set_message(message.into());
    pb
}

pub fn progress_bar(total: u64, prefix: &str, template: &str) -> Result<ProgressBar> {
    let pb = ProgressBar::new(total);
    pb.set_prefix(prefix.to_string());
    pb.set_style(
        ProgressStyle::with_template(template)
            .context("创建进度条样式失败")?
            .progress_chars("█▉▊▋▌▍▎▏  "),
    );
    Ok(pb)
}

pub fn build_tls_connector() -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

pub async fn load_locations(client: &Client, base_dir: &Path, pb: &ProgressBar) -> Result<Vec<Location>> {
    let locations_path = base_dir.join(LOCATIONS_FILE);
    let legacy_path = base_dir.join(LEGACY_LOCATION_FILE);

    let target_path = if fs::metadata(&locations_path).await.is_ok() {
        pb.println(format!("{} 已检测到 {}", "[缓存]".green().bold(), locations_path.display()));
        locations_path
    } else if fs::metadata(&legacy_path).await.is_ok() {
        pb.println(format!("{} 已检测到 {}", "[缓存]".green().bold(), legacy_path.display()));
        legacy_path
    } else {
        pb.println(format!(
            "{} 本地未找到 {}，开始下载...",
            "[下载]".cyan().bold(),
            LOCATIONS_FILE
        ));
        let body = client
            .get(LOCATIONS_URL)
            .send()
            .await
            .context("下载 locations.json 失败")?
            .error_for_status()
            .context("locations.json 返回状态异常")?
            .bytes()
            .await
            .context("读取 locations.json 内容失败")?;
        fs::write(&locations_path, &body)
            .await
            .context("写入 locations.json 失败")?;
        pb.println(format!("{} 已保存 {}", "[完成]".green().bold(), locations_path.display()));
        locations_path
    };

    let content = fs::read(&target_path)
        .await
        .with_context(|| format!("读取 {} 失败", target_path.display()))?;
    let locations = serde_json::from_slice::<Vec<Location>>(&content)
        .with_context(|| format!("解析 {} 失败", target_path.display()))?;
    Ok(locations)
}

pub async fn load_asn_db(
    client: &Client,
    base_dir: &Path,
    pb: &ProgressBar,
) -> Result<Option<Arc<Reader<Vec<u8>>>>> {
    let asn_path = base_dir.join(ASN_DB_FILE);

    if fs::metadata(&asn_path).await.is_err() {
        pb.println(format!("{} 本地未找到 {}，开始下载...", "[下载]".cyan().bold(), ASN_DB_FILE));
        let body = client
            .get(ASN_DB_URL)
            .send()
            .await
            .context("下载 ASN 数据库失败")?
            .error_for_status()
            .context("ASN 数据库返回状态异常")?
            .bytes()
            .await
            .context("读取 ASN 数据库内容失败")?;
        fs::write(&asn_path, &body)
            .await
            .context("写入 ASN 数据库失败")?;
        pb.println(format!("{} 已保存 {}", "[完成]".green().bold(), asn_path.display()));
    } else {
        pb.println(format!("{} 已检测到 {}", "[缓存]".green().bold(), asn_path.display()));
    }

    let bytes = fs::read(&asn_path)
        .await
        .with_context(|| format!("读取 {} 失败", asn_path.display()))?;
    let reader = Reader::from_source(bytes).context("加载 ASN 数据库失败")?;
    Ok(Some(Arc::new(reader)))
}

pub async fn read_ips(input_path: &Path, pb: &ProgressBar) -> Result<Vec<IpEntry>> {
    let content = fs::read_to_string(input_path)
        .await
        .with_context(|| format!("无法从文件中读取 IP: {}", input_path.display()))?;

    let mut ips = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parts = trimmed.split_whitespace().collect::<Vec<_>>();
        if parts.len() != 2 {
            pb.println(format!("{} 行格式错误: {}", "[跳过]".yellow().bold(), trimmed));
            continue;
        }

        let ip = parts[0].trim().to_string();
        let port = match parts[1].trim().parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                pb.println(format!("{} 端口格式错误: {}", "[跳过]".yellow().bold(), parts[1]));
                continue;
            }
        };

        ips.push(IpEntry { ip, port });
    }

    Ok(ips)
}
