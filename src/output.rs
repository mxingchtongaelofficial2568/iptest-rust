use std::{path::Path, time::Duration};

use anyhow::{Context, Result};
use owo_colors::OwoColorize;

use crate::model::ProbeResult;

pub async fn write_csv(path: &Path, rows: &[ProbeResult], enable_tls: bool, with_speed: bool) -> Result<()> {
    let path = path.to_path_buf();
    let rows = rows.to_vec();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let file = std::fs::File::create(&path)
            .with_context(|| format!("无法创建文件: {}", path.display()))?;
        let mut writer = csv::Writer::from_writer(file);

        if with_speed {
            writer.write_record([
                "IP地址",
                "端口号",
                "TLS",
                "数据中心",
                "源IP位置",
                "地区",
                "城市",
                "地区(中文)",
                "国家",
                "城市(中文)",
                "国旗",
                "网络延迟",
                "下载速度",
                "出站IP",
                "IP类型",
                "ASN号码",
                "ASN组织",
                "访问协议",
                "TLS版本",
                "SNI",
                "HTTP版本",
                "WARP",
                "Gateway",
                "RBI",
                "密钥交换",
                "时间戳",
            ])?;
        } else {
            writer.write_record([
                "IP地址",
                "端口号",
                "TLS",
                "数据中心",
                "源IP位置",
                "地区",
                "城市",
                "地区(中文)",
                "国家",
                "城市(中文)",
                "国旗",
                "网络延迟",
                "出站IP",
                "IP类型",
                "ASN号码",
                "ASN组织",
                "访问协议",
                "TLS版本",
                "SNI",
                "HTTP版本",
                "WARP",
                "Gateway",
                "RBI",
                "密钥交换",
                "时间戳",
            ])?;
        }

        for item in rows {
            let mut record = vec![
                item.ip,
                item.port.to_string(),
                enable_tls.to_string(),
                item.data_center,
                item.loc_code,
                item.region,
                item.city,
                item.region_zh,
                item.country,
                item.city_zh,
                item.emoji,
                format!("{} ms", item.latency_ms),
            ];

            if with_speed {
                record.push(format!("{:.0} kB/s", item.download_speed.unwrap_or(0.0)));
            }

            record.extend([
                item.outbound_ip,
                item.ip_type,
                item.autonomous_system_number.to_string(),
                item.autonomous_system_organization,
                item.visit_scheme,
                item.tls_version,
                item.sni,
                item.http_version,
                item.warp,
                item.gateway,
                item.rbi,
                item.kex,
                item.timestamp,
            ]);

            writer.write_record(record)?;
        }

        writer.flush().context("刷新 CSV 文件失败")?;
        Ok(())
    })
    .await
    .context("CSV 写入任务失败")??;

    Ok(())
}

pub fn print_summary(output_path: &Path, valid_count: usize, elapsed: Duration, with_speed: bool) {
    let mode = if with_speed { "延迟 + 下载测速" } else { "仅延迟探测" };
    println!();
    println!("{}", "════════════════════════════════════════════════════════════".blue());
    println!("{} {}", "运行模式:".bold(), mode.green().bold());
    println!("{} {}", "有效IP数量:".bold(), valid_count.to_string().cyan().bold());
    println!("{} {}", "结果文件:".bold(), output_path.display().to_string().yellow());
    println!("{} {:.2} 秒", "总耗时:".bold(), elapsed.as_secs_f64());
    println!("{}", "════════════════════════════════════════════════════════════".blue());
}
