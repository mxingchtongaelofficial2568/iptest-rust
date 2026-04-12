use std::time::Duration;

use clap::Parser;
use serde::Deserialize;

pub const DEFAULT_SPEED_URL: &str = "speed.cloudflare.com/__down?bytes=500000000";

#[derive(Debug, Clone, Parser)]
#[command(author, version, about = "Cloudflare 优选 IP 测速工具（Rust 版）")]
pub struct Opts {
    #[arg(long = "file", default_value = "ip.txt", help = "IP地址文件名称,格式为 ip port")]
    pub file: String,

    #[arg(long = "outfile", default_value = "ip.csv", help = "输出文件名称")]
    pub outfile: String,

    #[arg(long = "max", default_value_t = 100, help = "并发请求最大协程数")]
    pub max_threads: usize,

    #[arg(long = "speedtest", default_value_t = 5, help = "下载测速协程数量,设为0禁用测速")]
    pub speedtest: usize,

    #[arg(long = "url", default_value = DEFAULT_SPEED_URL, help = "测速文件地址")]
    pub url: String,

    #[arg(long = "tls", default_value_t = true, help = "是否启用TLS")]
    pub tls: bool,

    #[arg(long = "delay", default_value_t = 0, help = "延迟阈值(ms)，默认为0禁用延迟过滤")]
    pub delay: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Location {
    pub iata: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub cca2: String,
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

#[derive(Debug, Clone)]
pub struct IpEntry {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub ip: String,
    pub port: u16,
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
