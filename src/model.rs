use std::time::Duration;

use clap::Parser;
use serde::Deserialize;

pub const DEFAULT_SPEED_URL: &str = "speed.cloudflare.com/__down?bytes=500000000";

#[derive(Debug, Clone, Parser)]
#[command(author, version, about = "Cloudflare 优选 IP 测速工具（Rust 版）")]
pub struct Opts {
    #[arg(long = "file", default_value = "ip.txt", help = "IP地址文件名称,格式为 ip port 或 ip:port")]
    pub file: String,

    #[arg(long = "filter", help = "过滤重复IP，生成 文件名_filter.txt")]
    pub filter: bool,

    #[arg(long = "outfile", help = "输出CSV文件名称，未指定且开启--edgetunnel时不生成CSV")]
    pub outfile: Option<String>,

    #[arg(long = "max", default_value_t = 100, help = "并发请求最大协程数")]
    pub max_threads: usize,

    #[arg(long = "speedtest", default_value_t = 0, help = "下载测速协程数量,设为0禁用测速")]
    pub speedtest: usize,

    #[arg(long = "url", default_value = DEFAULT_SPEED_URL, help = "测速文件地址")]
    pub url: String,

    #[arg(long, default_value_t = false, help = "是否启用TLS")]
    pub tls: bool,

    #[arg(long = "delay", default_value_t = 0, help = "延迟阈值(ms)，默认为0禁用延迟过滤")]
    pub delay: u64,

    #[arg(long = "speed", default_value = "0", help = "最低下载速度阈值(MB/s)，低于此值的IP将被过滤，例如: --speed 0.5")]
    pub speed: String,

    #[arg(
        long = "edgetunnel",
        help = "生成EdgeTunnel分组txt文件，需指定输出名称 e.g. --edgetunnel edgetunnel.txt"
    )]
    pub edgetunnel: Option<String>,
}

impl Opts {
    pub fn speed_threshold_kbps(&self) -> f64 {
        let s = self.speed.trim().to_lowercase();
        let numeric_part = s.trim_end_matches("mb/s").trim_end_matches("mbps").trim();
        let mb_per_sec: f64 = numeric_part.parse().unwrap_or(0.0);
        mb_per_sec * 1024.0
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Location {
    pub iata: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub region_zh: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub city_zh: String,
    #[serde(default)]
    pub emoji: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpEntry {
    pub ip: String,
    pub port: u16,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub ip: String,
    pub port: u16,
    pub name: String,
    pub data_center: String,
    pub loc_code: String,
    pub region: String,
    pub city: String,
    pub region_zh: String,
    pub country: String,
    pub city_zh: String,
    pub emoji: String,
    pub latency_ms: u128,
    pub tcp_duration: Duration,
    pub outbound_ip: String,
    pub ip_type: String,
    pub visit_scheme: String,
    pub tls_version: String,
    pub sni: String,
    pub http_version: String,
    pub warp: String,
    pub gateway: String,
    pub rbi: String,
    pub kex: String,
    pub timestamp: String,
    pub autonomous_system_number: u32,
    pub autonomous_system_organization: String,
    pub download_speed: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct TargetUrl {
    pub host: String,
    pub path_and_query: String,
    pub referer: Option<String>,
}
