mod model;
mod output;
mod probe;
mod runtime;
mod edgetunnel;

use std::{
    borrow::Cow,
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::Parser;
use futures::{StreamExt, stream};
use indicatif::MultiProgress;
use mimalloc::MiMalloc;
use owo_colors::OwoColorize;
use reqwest::Client;

use crate::{
    model::Opts,
    output::{print_summary, write_csv},
    probe::{build_target_url, probe_ip, speed_test_ip},
    runtime::{
        build_tls_connector, load_asn_db, load_locations, normalize_args, progress_bar, read_ips,
        resolve_runtime_path, runtime_base_dir, spinner,
    },
};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let workers = std::thread::available_parallelism()
        .map(|n| n.get() * 2)
        .unwrap_or(8);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(128)
        .thread_name("iptest-worker")
        .max_io_events_per_tick(64)
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime");

    runtime.block_on(async {
        if let Err(err) = run().await {
            eprintln!("{} {}", "[错误]".red().bold(), err);
            std::process::exit(1);
        }
    });
}

fn update_min(target: &AtomicU64, candidate: u64) {
    let mut current = target.load(Ordering::Relaxed);
    while candidate < current {
        match target.compare_exchange(current, candidate, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

fn update_max(target: &AtomicU64, candidate: u64) {
    let mut current = target.load(Ordering::Relaxed);
    while candidate > current {
        match target.compare_exchange(current, candidate, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

fn format_best_latency_ms(value: u64) -> Cow<'static, str> {
    if value == u64::MAX {
        Cow::Borrowed("--")
    } else {
        Cow::Owned(format!("{value} ms"))
    }
}

fn format_best_speed_kbps(value: u64) -> Cow<'static, str> {
    if value == 0 {
        Cow::Borrowed("--")
    } else {
        Cow::Owned(format!("{value} kB/s"))
    }
}

async fn run() -> Result<()> {
    let opts = Opts::parse_from(normalize_args(std::env::args()));
    let base_dir = runtime_base_dir()?;
    let input_path = resolve_runtime_path(&base_dir, &opts.file);
    let csv_path = opts.outfile.as_ref().map(|f| resolve_runtime_path(&base_dir, f));
    let edgetunnel_path = opts.edgetunnel.as_ref().map(|f| resolve_runtime_path(&base_dir, f));
    let should_write_csv = csv_path.is_some() || edgetunnel_path.is_none();
    let csv_path = csv_path.unwrap_or_else(|| resolve_runtime_path(&base_dir, "ip.csv"));
    let started = Instant::now();

    let multi = Arc::new(MultiProgress::new());
    let setup_pb = multi.add(spinner("初始化运行环境..."));

    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("Mozilla/5.0 (iptest-rust)")
        .build()
        .context("创建下载客户端失败")?;

    let tls_connector = build_tls_connector();

    let locations = load_locations(&client, &base_dir, &setup_pb).await?;
    let location_map = Arc::new(
        locations
            .into_iter()
            .map(|loc| (loc.iata.clone(), loc))
            .collect::<HashMap<_, _>>(),
    );

    let asn_db = match load_asn_db(&client, &base_dir, &setup_pb).await {
        Ok(db) => db,
        Err(err) => {
            setup_pb.println(format!("{} ASN数据库不可用: {}", "[警告]".yellow().bold(), err));
            None
        }
    };

    let ips = read_ips(&input_path, &setup_pb).await?;
    if ips.is_empty() {
        setup_pb.finish_and_clear();
        println!("{} 没有找到可测试的 IP 记录", "[提示]".yellow().bold());
        return Ok(());
    }

    setup_pb.finish_and_clear();
    println!(
        "{} {} | 运行目录: {} | 待扫描 IP: {}",
        "✓".green().bold(),
        "初始化完成",
        base_dir.display(),
        ips.len()
    );

    let valid_count = Arc::new(AtomicUsize::new(0));
    let best_latency_ms = Arc::new(AtomicU64::new(u64::MAX));
    let scan_pb = multi.add(progress_bar(
        ips.len() as u64,
        "探测有效 IP",
        "{spinner:.cyan} {prefix:.bold.dim} [{elapsed_precise}<{eta_precise}] [{bar:40.cyan/blue}] {pos}/{len} {per_sec} {msg}",
    )?);
    scan_pb.set_message("有效 0 / 最快 --".to_string());

    let scan_parallelism = opts.max_threads.max(1);
    let mut probe_results = stream::iter(ips.into_iter().map(|entry| {
        let location_map = Arc::clone(&location_map);
        let tls_connector = tls_connector.clone();
        let asn_db = asn_db.clone();
        let scan_pb = scan_pb.clone();
        let valid_count = Arc::clone(&valid_count);
        let best_latency_ms = Arc::clone(&best_latency_ms);
        let opts = opts.clone();
        async move {
            let result = probe_ip(entry, &opts, &location_map, asn_db.as_ref(), &tls_connector).await;
            if let Some(ref item) = result {
                let found = valid_count.fetch_add(1, Ordering::Relaxed) + 1;
                update_min(&best_latency_ms, item.latency_ms as u64);
                let place = if item.city_zh.is_empty() {
                    "位置未知".to_string()
                } else {
                    item.city_zh.clone()
                };
                scan_pb.println(format!(
                    "{} {}:{}  {}  {}  {} ms",
                    "✓".green().bold(),
                    item.ip.cyan(),
                    item.port.to_string().cyan(),
                    place,
                    item.ip_type.as_str().blue(),
                    item.latency_ms.to_string().yellow()
                ));
                scan_pb.set_message(format!(
                    "有效 {} / 最快 {}",
                    found,
                    format_best_latency_ms(best_latency_ms.load(Ordering::Relaxed)),
                ));
            } else {
                scan_pb.set_message(format!(
                    "有效 {} / 最快 {}",
                    valid_count.load(Ordering::Relaxed),
                    format_best_latency_ms(best_latency_ms.load(Ordering::Relaxed)),
                ));
            }
            scan_pb.inc(1);
            result
        }
    }))
    .buffer_unordered(scan_parallelism);

    let mut results = Vec::new();
    while let Some(item) = probe_results.next().await {
        if let Some(row) = item {
            results.push(row);
        }
    }

    scan_pb.finish_with_message(format!("扫描完成 | 有效 IP: {}", results.len()));

    if results.is_empty() {
        println!("{} 没有发现有效的 IP", "[结果]".yellow().bold());
        return Ok(());
    }

    if opts.speedtest > 0 {
        let speed_target = build_target_url(&opts.url, opts.tls)?;
        let speed_pb = multi.add(progress_bar(
            results.len() as u64,
            "下载测速",
            "{spinner:.green} {prefix:.bold.dim} [{elapsed_precise}<{eta_precise}] [{bar:40.green/blue}] {pos}/{len} {per_sec} {msg}",
        )?);
        speed_pb.set_message("最快 -- | 已完成 0/0".to_string());

        let speed_parallelism = opts.speedtest.max(1);
        let total = results.len();
        let speed_done = Arc::new(AtomicUsize::new(0));
        let best_speed_kbps = Arc::new(AtomicU64::new(0));
        let mut speed_stream = stream::iter(results.into_iter().map(|item| {
            let tls_connector = tls_connector.clone();
            let speed_pb = speed_pb.clone();
            let speed_target = speed_target.clone();
            let speed_done = Arc::clone(&speed_done);
            let best_speed_kbps = Arc::clone(&best_speed_kbps);
            let opts = opts.clone();
            async move {
                let speed = speed_test_ip(&item.ip, item.port, &speed_target, opts.tls, &tls_connector).await;
                let mut updated = item;
                updated.download_speed = Some(speed);
                let rounded_speed = speed.max(0.0).round() as u64;
                update_max(&best_speed_kbps, rounded_speed);
                let completed = speed_done.fetch_add(1, Ordering::Relaxed) + 1;
                speed_pb.inc(1);
                speed_pb.set_message(format!(
                    "最快 {} | 已完成 {}/{}",
                    format_best_speed_kbps(best_speed_kbps.load(Ordering::Relaxed)),
                    completed,
                    total
                ));
                speed_pb.println(format!(
                    "{} {}:{}  {}  {:.0} kB/s",
                    "⇣".magenta().bold(),
                    updated.ip.cyan(),
                    updated.port.to_string().cyan(),
                    if updated.city_zh.is_empty() { "位置未知" } else { &updated.city_zh },
                    speed
                ));
                updated
            }
        }))
        .buffer_unordered(speed_parallelism);

        let mut speed_results = Vec::new();
        while let Some(item) = speed_stream.next().await {
            speed_results.push(item);
        }

        speed_pb.finish_with_message("测速完成".to_string());
        speed_results.sort_by(|a, b| {
            b.download_speed
                .unwrap_or(0.0)
                .partial_cmp(&a.download_speed.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        if should_write_csv {
            write_csv(&csv_path, &speed_results, opts.tls, true).await?;
        }
        if let Some(ref txt_path) = edgetunnel_path {
            edgetunnel::convert(&speed_results, txt_path)?;
        }
        let csv_output = should_write_csv.then(|| csv_path.as_path());
        print_summary(csv_output, speed_results.len(), started.elapsed(), true);
    } else {
        results.sort_by_key(|item| item.tcp_duration);
        if should_write_csv {
            write_csv(&csv_path, &results, opts.tls, false).await?;
        }
        if let Some(ref txt_path) = edgetunnel_path {
            edgetunnel::convert(&results, txt_path)?;
        }
        let csv_output = should_write_csv.then(|| csv_path.as_path());
        print_summary(csv_output, results.len(), started.elapsed(), false);
    }

    Ok(())
}
