use std::{collections::BTreeMap, fs, io::Write, net::IpAddr, path::Path, str::FromStr};

use anyhow::{Context, Result};
use owo_colors::OwoColorize;

use crate::model::ProbeResult;

struct Entry {
    score: f64,
    line: String,
}

pub fn convert(data: &[ProbeResult], output_path: &Path) -> Result<()> {
    let mut countries: BTreeMap<&str, Vec<Entry>> = BTreeMap::new();

    for item in data {
        let speed_kbps = item.download_speed.unwrap_or(0.0);
        let latency = item.latency_ms;

        let speed_mb = speed_kbps / 1024.0;
        let score = speed_mb / (latency.max(1) as f64);

        let speed_str = format!("{speed_mb:.2}MB/s");
        let latency_str = format!("{latency}ms");
        let metric = format!("{speed_str}, {latency_str}");

        let country = if item.country.is_empty() { "Unknown" } else { &item.country };

        let line = match IpAddr::from_str(&item.ip) {
            Ok(IpAddr::V6(_)) => {
                if item.name.is_empty() {
                    format!("[{}]:{}#{}({})", item.ip, item.port, country, metric)
                } else {
                    format!("[{}]:{}#{} ({} {})", item.ip, item.port, country, metric, item.name)
                }
            }
            _ => {
                if item.name.is_empty() {
                    format!("{}:{}#{}({})", item.ip, item.port, country, metric)
                } else {
                    format!("{}:{}#{} ({} {})", item.ip, item.port, country, metric, item.name)
                }
            }
        };

        countries.entry(country).or_default().push(Entry { score, line });
    }

    let mut file = fs::File::create(output_path)
        .with_context(|| format!("无法创建文件: {}", output_path.display()))?;

    for entries in countries.values_mut() {
        entries.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    }

    for (country, entries) in &countries {
        let header = format!("# === {} ({}) ===\n", country, entries.len());
        file.write_all(header.as_bytes())?;
        for entry in entries {
            file.write_all(entry.line.as_bytes())?;
            file.write_all(b"\n")?;
        }
        file.write_all(b"\n")?;
    }

    file.flush()?;

    let total: usize = countries.values().map(|v| v.len()).sum();
    println!();
    println!("{} {}", "EdgeTunnel 转换:".green().bold(), "完成".green());
    println!("  📦 保留 IP: {total}   🌍 国家/地区: {}", countries.len());
    println!("  💾 输出文件: {}", output_path.display());

    Ok(())
}
