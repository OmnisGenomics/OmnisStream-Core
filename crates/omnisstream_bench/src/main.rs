use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, ValueEnum};
use serde::Serialize;

use omnisstream::{Manifest, PartStore, Reader};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Preset {
    Default,
    Ci,
    Wsl,
}

#[derive(Debug, Parser)]
#[command(name = "omnisstream_bench")]
struct Args {
    /// Output JSON path.
    #[arg(long, default_value = "bench.json")]
    out: PathBuf,

    /// Predefined size/runtime settings.
    #[arg(long, value_enum, default_value_t = Preset::Default)]
    preset: Preset,

    /// Input size (MiB) for ingest/verify scenarios.
    #[arg(long)]
    file_size_mib: Option<u64>,

    /// Part size (MiB) for ingest.
    #[arg(long)]
    part_size_mib: Option<u64>,

    /// Range read length (KiB) for the random range scenario.
    #[arg(long)]
    range_len_kib: Option<u64>,

    /// Number of random range read operations.
    #[arg(long)]
    range_ops: Option<u64>,

    /// RNG seed for range offsets (deterministic).
    #[arg(long)]
    seed: Option<u64>,

    /// Disable fsync/directory fsync for ingest (benchmarking only; breaks durability guarantees).
    #[arg(long)]
    relaxed_durability: bool,

    /// Enable prototype group commit batching (Linux only).
    #[cfg(feature = "group-commit")]
    #[arg(long)]
    group_commit: bool,

    /// Max operations per group commit barrier batch.
    #[cfg(feature = "group-commit")]
    #[arg(long, default_value_t = 32)]
    group_commit_max_ops: usize,

    /// Max time window (ms) to batch operations before the barrier.
    #[cfg(feature = "group-commit")]
    #[arg(long, default_value_t = 50)]
    group_commit_window_ms: u64,
}

#[derive(Clone, Debug)]
struct BenchConfig {
    preset: Preset,
    file_size_bytes: u64,
    part_size_bytes: u64,
    range_len_bytes: u64,
    range_ops: u64,
    seed: u64,
    relaxed_durability: bool,
    group_commit: bool,
    group_commit_max_ops: usize,
    group_commit_window_ms: u64,
}

impl BenchConfig {
    fn from_args(args: Args) -> Self {
        let group_commit = {
            #[cfg(feature = "group-commit")]
            {
                args.group_commit
            }
            #[cfg(not(feature = "group-commit"))]
            {
                false
            }
        };
        let group_commit_max_ops = {
            #[cfg(feature = "group-commit")]
            {
                args.group_commit_max_ops
            }
            #[cfg(not(feature = "group-commit"))]
            {
                0
            }
        };
        let group_commit_window_ms = {
            #[cfg(feature = "group-commit")]
            {
                args.group_commit_window_ms
            }
            #[cfg(not(feature = "group-commit"))]
            {
                0
            }
        };

        let mut cfg = match args.preset {
            Preset::Default => Self {
                preset: args.preset,
                file_size_bytes: 256 * 1024 * 1024,
                part_size_bytes: 4 * 1024 * 1024,
                range_len_bytes: 64 * 1024,
                range_ops: 2000,
                seed: 1,
                relaxed_durability: args.relaxed_durability,
                group_commit,
                group_commit_max_ops,
                group_commit_window_ms,
            },
            Preset::Ci => Self {
                preset: args.preset,
                file_size_bytes: 8 * 1024 * 1024,
                part_size_bytes: 1024 * 1024,
                range_len_bytes: 4 * 1024,
                range_ops: 200,
                seed: 1,
                relaxed_durability: args.relaxed_durability,
                group_commit,
                group_commit_max_ops,
                group_commit_window_ms,
            },
            Preset::Wsl => Self {
                preset: args.preset,
                file_size_bytes: 256 * 1024 * 1024,
                part_size_bytes: 8 * 1024 * 1024,
                range_len_bytes: 64 * 1024,
                range_ops: 2000,
                seed: 1,
                relaxed_durability: args.relaxed_durability,
                group_commit,
                group_commit_max_ops,
                group_commit_window_ms,
            },
        };

        if let Some(mib) = args.file_size_mib {
            cfg.file_size_bytes = mib.saturating_mul(1024 * 1024);
        }
        if let Some(mib) = args.part_size_mib {
            cfg.part_size_bytes = mib.saturating_mul(1024 * 1024).max(1);
        }
        if let Some(kib) = args.range_len_kib {
            cfg.range_len_bytes = kib.saturating_mul(1024);
        }
        if let Some(ops) = args.range_ops {
            cfg.range_ops = ops.max(1);
        }
        if let Some(seed) = args.seed {
            cfg.seed = seed;
        }

        if cfg.file_size_bytes == 0 {
            cfg.file_size_bytes = 1;
        }
        if cfg.range_len_bytes == 0 {
            cfg.range_len_bytes = 1;
        }

        cfg
    }
}

#[derive(Debug, Serialize)]
struct BenchJson {
    schema_version: u32,
    generated_unix_ms: u64,
    tool_version: String,
    git_head: Option<String>,
    spec_pin: Option<String>,
    params: BenchParamsJson,
    results: BenchResultsJson,
}

#[derive(Debug, Serialize)]
struct BenchParamsJson {
    preset: String,
    file_size_bytes: u64,
    part_size_bytes: u64,
    range_len_bytes: u64,
    range_ops: u64,
    seed: u64,
    relaxed_durability: bool,
    group_commit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    group_commit_max_ops: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group_commit_window_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct BenchResultsJson {
    ingest: BytesScenarioJson,
    verify: BytesScenarioJson,
    range_reads: RangeScenarioJson,
}

#[derive(Debug, Serialize)]
struct BytesScenarioJson {
    ok: bool,
    error: Option<String>,
    wall_seconds: f64,
    bytes: u64,
    bytes_per_sec: f64,
    parts: u64,
    avg_part_wall_ms: Option<f64>,
    cpu_seconds: Option<f64>,
    cpu_percent: Option<f64>,
    peak_rss_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group_commit_metrics: Option<GroupCommitMetricsJson>,
}

#[derive(Debug, Serialize)]
struct RangeScenarioJson {
    ok: bool,
    error: Option<String>,
    wall_seconds: f64,
    ops: u64,
    ops_per_sec: f64,
    bytes: u64,
    bytes_per_sec: f64,
    cpu_seconds: Option<f64>,
    cpu_percent: Option<f64>,
    peak_rss_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
struct GroupCommitMetricsJson {
    syncfs_calls: u64,
    syncfs_errors: u64,
    write_tokens: u64,
    waiter_tokens: u64,
    syncfs_wall_ms: u64,
    worker_wait_ms: u64,
    max_write_batch: u64,
    max_total_batch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    avg_write_batch: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    avg_syncfs_wall_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    avg_worker_wait_ms: Option<f64>,
}

#[cfg(feature = "group-commit")]
fn group_commit_metrics_json(m: omnisstream::api::GroupCommitMetrics) -> GroupCommitMetricsJson {
    let total_tokens = m.write_tokens.saturating_add(m.waiter_tokens);
    let avg_write_batch = if m.syncfs_calls > 0 {
        Some(m.write_tokens as f64 / m.syncfs_calls as f64)
    } else {
        None
    };
    let avg_syncfs_wall_ms = if m.syncfs_calls > 0 {
        Some(m.syncfs_wall_ms as f64 / m.syncfs_calls as f64)
    } else {
        None
    };
    let avg_worker_wait_ms = if total_tokens > 0 {
        Some(m.worker_wait_ms as f64 / total_tokens as f64)
    } else {
        None
    };

    GroupCommitMetricsJson {
        syncfs_calls: m.syncfs_calls,
        syncfs_errors: m.syncfs_errors,
        write_tokens: m.write_tokens,
        waiter_tokens: m.waiter_tokens,
        syncfs_wall_ms: m.syncfs_wall_ms,
        worker_wait_ms: m.worker_wait_ms,
        max_write_batch: m.max_write_batch,
        max_total_batch: m.max_total_batch,
        avg_write_batch,
        avg_syncfs_wall_ms,
        avg_worker_wait_ms,
    }
}

#[derive(Clone, Copy, Debug)]
struct UsageSnapshot {
    cpu_user_nanos: Option<u64>,
    cpu_sys_nanos: Option<u64>,
    peak_rss_bytes: Option<u64>,
}

impl UsageSnapshot {
    fn now() -> Self {
        #[cfg(unix)]
        {
            unsafe {
                let mut r: libc::rusage = std::mem::zeroed();
                if libc::getrusage(libc::RUSAGE_SELF, &mut r as *mut libc::rusage) != 0 {
                    return Self {
                        cpu_user_nanos: None,
                        cpu_sys_nanos: None,
                        peak_rss_bytes: None,
                    };
                }
                let user = (r.ru_utime.tv_sec as i128)
                    .saturating_mul(1_000_000_000)
                    .saturating_add((r.ru_utime.tv_usec as i128).saturating_mul(1_000));
                let sys = (r.ru_stime.tv_sec as i128)
                    .saturating_mul(1_000_000_000)
                    .saturating_add((r.ru_stime.tv_usec as i128).saturating_mul(1_000));

                // Linux reports ru_maxrss in KiB, macOS in bytes. We only promise "if feasible",
                // so treat this as best-effort and keep the field optional.
                let maxrss = r.ru_maxrss;
                let peak = if maxrss <= 0 {
                    None
                } else {
                    let v = maxrss as u64;
                    #[cfg(target_os = "macos")]
                    {
                        Some(v)
                    }
                    #[cfg(not(target_os = "macos"))]
                    {
                        Some(v.saturating_mul(1024))
                    }
                };

                Self {
                    cpu_user_nanos: Some(user.max(0) as u64),
                    cpu_sys_nanos: Some(sys.max(0) as u64),
                    peak_rss_bytes: peak,
                }
            }
        }

        #[cfg(not(unix))]
        {
            Self {
                cpu_user_nanos: None,
                cpu_sys_nanos: None,
                peak_rss_bytes: None,
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Measured {
    wall: Duration,
    cpu_seconds: Option<f64>,
    cpu_percent: Option<f64>,
    peak_rss_bytes: Option<u64>,
}

fn measure<F, T>(f: F) -> (Measured, anyhow::Result<T>)
where
    F: FnOnce() -> anyhow::Result<T>,
{
    let start_usage = UsageSnapshot::now();
    let start = Instant::now();
    let res = f();
    let wall = start.elapsed();
    let end_usage = UsageSnapshot::now();

    let cpu_seconds = match (start_usage.cpu_user_nanos, start_usage.cpu_sys_nanos) {
        (Some(us), Some(ss)) => match (end_usage.cpu_user_nanos, end_usage.cpu_sys_nanos) {
            (Some(ue), Some(se)) => {
                let delta = ue.saturating_sub(us).saturating_add(se.saturating_sub(ss));
                Some(delta as f64 / 1_000_000_000.0)
            }
            _ => None,
        },
        _ => None,
    };

    let cpu_percent = cpu_seconds.and_then(|cpu| {
        let wall_s = wall.as_secs_f64();
        if wall_s > 0.0 {
            Some((cpu / wall_s) * 100.0)
        } else {
            None
        }
    });

    (
        Measured {
            wall,
            cpu_seconds,
            cpu_percent,
            peak_rss_bytes: end_usage.peak_rss_bytes.or(start_usage.peak_rss_bytes),
        },
        res,
    )
}

fn generated_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

fn read_optional_trimmed(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn git_head() -> Option<String> {
    // Works in a normal repo checkout; returns None for vendored/packaged sources.
    let head = read_optional_trimmed(".git/HEAD")?;
    if let Some(r) = head.strip_prefix("ref:") {
        let r = r.trim();
        read_optional_trimmed(Path::new(".git").join(r))
    } else {
        Some(head)
    }
}

fn write_deterministic_file(path: &Path, size: u64) -> io::Result<()> {
    let mut f = File::create(path)?;

    let mut rng = SplitMix64::new(0x4f6d_6e69_7353_7472); // "OmnisStr" seed-ish
    let mut remaining = size;
    let mut buf = vec![0_u8; 1024 * 1024];

    while remaining > 0 {
        // Fill buffer deterministically (fast enough for our harness).
        for chunk in buf.chunks_exact_mut(8) {
            chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
        }

        let n = (buf.len() as u64).min(remaining) as usize;
        f.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    f.sync_all()?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

fn throughput(bytes: u64, wall: Duration) -> f64 {
    let wall_s = wall.as_secs_f64();
    if wall_s > 0.0 {
        bytes as f64 / wall_s
    } else {
        0.0
    }
}

fn qps(ops: u64, wall: Duration) -> f64 {
    let wall_s = wall.as_secs_f64();
    if wall_s > 0.0 {
        ops as f64 / wall_s
    } else {
        0.0
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let out_path = args.out.clone();
    let cfg = BenchConfig::from_args(args);

    if cfg.relaxed_durability {
        eprintln!(
            "WARNING: --relaxed-durability disables fsync/directory fsync; benchmarking only (data loss on crash likely)."
        );
        omnisstream::api::set_relaxed_durability(true);
    }

    if cfg.group_commit {
        eprintln!(
            "WARNING: --group-commit batches durability barriers (syncfs); prototype only (use on dedicated filesystems)."
        );

        #[cfg(all(feature = "group-commit", target_os = "linux"))]
        {
            if cfg.group_commit_max_ops == 0 {
                anyhow::bail!("--group-commit-max-ops must be >= 1");
            }
            omnisstream::api::set_group_commit_config(Some(omnisstream::api::GroupCommitConfig {
                max_ops: cfg.group_commit_max_ops,
                window_ms: cfg.group_commit_window_ms,
            }));
        }

        #[cfg(all(feature = "group-commit", not(target_os = "linux")))]
        {
            eprintln!("WARNING: --group-commit is only supported on Linux; ignoring.");
        }
    }

    let spec_pin = read_optional_trimmed("SPEC_PIN.txt");
    let git_head = git_head();
    let tool_version = env!("CARGO_PKG_VERSION").to_string();

    let (ingest_result, verify_result, range_result) = match run_bench(&cfg) {
        Ok(v) => v,
        Err(e) => {
            let err = e.to_string();
            let wall = 0.0;
            let ingest = BytesScenarioJson {
                ok: false,
                error: Some(err.clone()),
                wall_seconds: wall,
                bytes: cfg.file_size_bytes,
                bytes_per_sec: 0.0,
                parts: 0,
                avg_part_wall_ms: None,
                cpu_seconds: None,
                cpu_percent: None,
                peak_rss_bytes: None,
                group_commit_metrics: None,
            };
            let verify = BytesScenarioJson {
                ok: false,
                error: Some(err.clone()),
                wall_seconds: wall,
                bytes: cfg.file_size_bytes,
                bytes_per_sec: 0.0,
                parts: 0,
                avg_part_wall_ms: None,
                cpu_seconds: None,
                cpu_percent: None,
                peak_rss_bytes: None,
                group_commit_metrics: None,
            };
            let range_reads = RangeScenarioJson {
                ok: false,
                error: Some(err),
                wall_seconds: wall,
                ops: cfg.range_ops,
                ops_per_sec: 0.0,
                bytes: cfg.range_ops.saturating_mul(cfg.range_len_bytes),
                bytes_per_sec: 0.0,
                cpu_seconds: None,
                cpu_percent: None,
                peak_rss_bytes: None,
            };
            (ingest, verify, range_reads)
        }
    };

    let bench = BenchJson {
        schema_version: 1,
        generated_unix_ms: generated_unix_ms(),
        tool_version,
        git_head,
        spec_pin,
        params: BenchParamsJson {
            preset: format!("{:?}", cfg.preset).to_lowercase(),
            file_size_bytes: cfg.file_size_bytes,
            part_size_bytes: cfg.part_size_bytes,
            range_len_bytes: cfg.range_len_bytes,
            range_ops: cfg.range_ops,
            seed: cfg.seed,
            relaxed_durability: cfg.relaxed_durability,
            group_commit: cfg.group_commit,
            group_commit_max_ops: cfg.group_commit.then_some(cfg.group_commit_max_ops),
            group_commit_window_ms: cfg.group_commit.then_some(cfg.group_commit_window_ms),
        },
        results: BenchResultsJson {
            ingest: ingest_result,
            verify: verify_result,
            range_reads: range_result,
        },
    };

    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    std::fs::write(&out_path, serde_json::to_string_pretty(&bench)?)?;
    eprintln!("wrote {}", out_path.display());

    if !bench.results.ingest.ok || !bench.results.verify.ok || !bench.results.range_reads.ok {
        anyhow::bail!("one or more benchmark scenarios failed");
    }
    Ok(())
}

fn run_bench(
    cfg: &BenchConfig,
) -> anyhow::Result<(BytesScenarioJson, BytesScenarioJson, RangeScenarioJson)> {
    let tmp = tempfile::tempdir()?;
    let input_path = tmp.path().join("input.bin");
    write_deterministic_file(&input_path, cfg.file_size_bytes)?;

    let repo_root = tmp.path().join("repo");

    #[cfg(feature = "group-commit")]
    if cfg.group_commit {
        omnisstream::api::reset_group_commit_metrics();
    }

    // Ingest
    let (ingest_measured, ingest_res) = measure(|| {
        omnisstream::ingest_file(&repo_root, &input_path, cfg.part_size_bytes)
            .map_err(|e| anyhow::anyhow!(e))
    });

    let (ingest, ingest_res) = match ingest_res {
        Ok(r) => {
            let metrics = {
                #[cfg(feature = "group-commit")]
                {
                    if cfg.group_commit {
                        omnisstream::api::group_commit_metrics().map(group_commit_metrics_json)
                    } else {
                        None
                    }
                }
                #[cfg(not(feature = "group-commit"))]
                {
                    None
                }
            };
            (
                ingest_json(
                    cfg.file_size_bytes,
                    cfg.part_size_bytes,
                    ingest_measured,
                    metrics,
                ),
                Some(r),
            )
        }
        Err(e) => (
            BytesScenarioJson {
                ok: false,
                error: Some(e.to_string()),
                wall_seconds: ingest_measured.wall.as_secs_f64(),
                bytes: cfg.file_size_bytes,
                bytes_per_sec: throughput(cfg.file_size_bytes, ingest_measured.wall),
                parts: 0,
                avg_part_wall_ms: None,
                cpu_seconds: ingest_measured.cpu_seconds,
                cpu_percent: ingest_measured.cpu_percent,
                peak_rss_bytes: ingest_measured.peak_rss_bytes,
                group_commit_metrics: None,
            },
            None,
        ),
    };

    let Some(ingest_res) = ingest_res else {
        let skipped = "skipped due to ingest failure".to_string();
        return Ok((
            ingest,
            BytesScenarioJson {
                ok: false,
                error: Some(skipped.clone()),
                wall_seconds: 0.0,
                bytes: cfg.file_size_bytes,
                bytes_per_sec: 0.0,
                parts: 0,
                avg_part_wall_ms: None,
                cpu_seconds: None,
                cpu_percent: None,
                peak_rss_bytes: None,
                group_commit_metrics: None,
            },
            RangeScenarioJson {
                ok: false,
                error: Some(skipped),
                wall_seconds: 0.0,
                ops: cfg.range_ops,
                ops_per_sec: 0.0,
                bytes: cfg.range_ops.saturating_mul(cfg.range_len_bytes),
                bytes_per_sec: 0.0,
                cpu_seconds: None,
                cpu_percent: None,
                peak_rss_bytes: None,
            },
        ));
    };

    // Verify
    let (verify_measured, verify_res) =
        measure(|| verify_manifest(&repo_root, &ingest_res.manifest));
    let verify = match verify_res {
        Ok(summary) => BytesScenarioJson {
            ok: true,
            error: None,
            wall_seconds: verify_measured.wall.as_secs_f64(),
            bytes: summary.bytes,
            bytes_per_sec: throughput(summary.bytes, verify_measured.wall),
            parts: summary.parts as u64,
            avg_part_wall_ms: avg_part_wall_ms(verify_measured.wall, summary.parts as u64),
            cpu_seconds: verify_measured.cpu_seconds,
            cpu_percent: verify_measured.cpu_percent,
            peak_rss_bytes: verify_measured.peak_rss_bytes,
            group_commit_metrics: None,
        },
        Err(e) => BytesScenarioJson {
            ok: false,
            error: Some(e.to_string()),
            wall_seconds: verify_measured.wall.as_secs_f64(),
            bytes: cfg.file_size_bytes,
            bytes_per_sec: throughput(cfg.file_size_bytes, verify_measured.wall),
            parts: 0,
            avg_part_wall_ms: None,
            cpu_seconds: verify_measured.cpu_seconds,
            cpu_percent: verify_measured.cpu_percent,
            peak_rss_bytes: verify_measured.peak_rss_bytes,
            group_commit_metrics: None,
        },
    };

    // Range reads
    let (range_measured, range_res) =
        measure(|| range_reads(&repo_root, &ingest_res.manifest, cfg));
    let range_reads = match range_res {
        Ok((ops, bytes)) => RangeScenarioJson {
            ok: true,
            error: None,
            wall_seconds: range_measured.wall.as_secs_f64(),
            ops,
            ops_per_sec: qps(ops, range_measured.wall),
            bytes,
            bytes_per_sec: throughput(bytes, range_measured.wall),
            cpu_seconds: range_measured.cpu_seconds,
            cpu_percent: range_measured.cpu_percent,
            peak_rss_bytes: range_measured.peak_rss_bytes,
        },
        Err(e) => RangeScenarioJson {
            ok: false,
            error: Some(e.to_string()),
            wall_seconds: range_measured.wall.as_secs_f64(),
            ops: cfg.range_ops,
            ops_per_sec: qps(cfg.range_ops, range_measured.wall),
            bytes: cfg.range_ops.saturating_mul(cfg.range_len_bytes),
            bytes_per_sec: throughput(
                cfg.range_ops.saturating_mul(cfg.range_len_bytes),
                range_measured.wall,
            ),
            cpu_seconds: range_measured.cpu_seconds,
            cpu_percent: range_measured.cpu_percent,
            peak_rss_bytes: range_measured.peak_rss_bytes,
        },
    };

    Ok((ingest, verify, range_reads))
}

fn ingest_json(
    bytes: u64,
    part_size_bytes: u64,
    measured: Measured,
    group_commit_metrics: Option<GroupCommitMetricsJson>,
) -> BytesScenarioJson {
    let part_size_bytes = part_size_bytes.max(1);
    let parts = bytes.div_ceil(part_size_bytes);
    BytesScenarioJson {
        ok: true,
        error: None,
        wall_seconds: measured.wall.as_secs_f64(),
        bytes,
        bytes_per_sec: throughput(bytes, measured.wall),
        parts,
        avg_part_wall_ms: avg_part_wall_ms(measured.wall, parts),
        cpu_seconds: measured.cpu_seconds,
        cpu_percent: measured.cpu_percent,
        peak_rss_bytes: measured.peak_rss_bytes,
        group_commit_metrics,
    }
}

fn avg_part_wall_ms(wall: Duration, parts: u64) -> Option<f64> {
    if parts == 0 {
        return None;
    }
    Some((wall.as_secs_f64() / parts as f64) * 1000.0)
}

fn verify_manifest(
    repo_root: &Path,
    manifest: &Manifest,
) -> anyhow::Result<omnisstream::api::VerifySummary> {
    let mut reader = Reader::new(manifest.clone(), repo_root);
    if reader.manifest().needs_part_store() {
        let store = PartStore::new(repo_root.join("parts"))?;
        reader = reader.with_part_store(store);
    }
    Ok(reader.verify()?)
}

fn range_reads(
    repo_root: &Path,
    manifest: &Manifest,
    cfg: &BenchConfig,
) -> anyhow::Result<(u64, u64)> {
    let mut reader = Reader::new(manifest.clone(), repo_root);
    if reader.manifest().needs_part_store() {
        let store = PartStore::new(repo_root.join("parts"))?;
        reader = reader.with_part_store(store);
    }

    let obj_len = cfg.file_size_bytes;
    let len = cfg.range_len_bytes.min(obj_len).max(1);
    let max_offset = obj_len.saturating_sub(len);

    let mut rng = SplitMix64::new(cfg.seed);
    let mut sink = io::sink();
    for _ in 0..cfg.range_ops {
        let offset = if max_offset == 0 {
            0
        } else {
            rng.next_u64() % (max_offset + 1)
        };
        reader.range(offset, len, &mut sink)?;
    }

    Ok((cfg.range_ops, cfg.range_ops.saturating_mul(len)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_schema_has_stable_top_level_fields() {
        let cfg = BenchConfig {
            preset: Preset::Ci,
            file_size_bytes: 1,
            part_size_bytes: 1,
            range_len_bytes: 1,
            range_ops: 1,
            seed: 1,
            relaxed_durability: false,
            group_commit: false,
            group_commit_max_ops: 0,
            group_commit_window_ms: 0,
        };

        let bench = BenchJson {
            schema_version: 1,
            generated_unix_ms: 0,
            tool_version: "0.0.0".to_string(),
            git_head: None,
            spec_pin: None,
            params: BenchParamsJson {
                preset: "ci".to_string(),
                file_size_bytes: cfg.file_size_bytes,
                part_size_bytes: cfg.part_size_bytes,
                range_len_bytes: cfg.range_len_bytes,
                range_ops: cfg.range_ops,
                seed: cfg.seed,
                relaxed_durability: cfg.relaxed_durability,
                group_commit: false,
                group_commit_max_ops: None,
                group_commit_window_ms: None,
            },
            results: BenchResultsJson {
                ingest: BytesScenarioJson {
                    ok: true,
                    error: None,
                    wall_seconds: 0.0,
                    bytes: 0,
                    bytes_per_sec: 0.0,
                    parts: 0,
                    avg_part_wall_ms: None,
                    cpu_seconds: None,
                    cpu_percent: None,
                    peak_rss_bytes: None,
                    group_commit_metrics: None,
                },
                verify: BytesScenarioJson {
                    ok: true,
                    error: None,
                    wall_seconds: 0.0,
                    bytes: 0,
                    bytes_per_sec: 0.0,
                    parts: 0,
                    avg_part_wall_ms: None,
                    cpu_seconds: None,
                    cpu_percent: None,
                    peak_rss_bytes: None,
                    group_commit_metrics: None,
                },
                range_reads: RangeScenarioJson {
                    ok: true,
                    error: None,
                    wall_seconds: 0.0,
                    ops: 0,
                    ops_per_sec: 0.0,
                    bytes: 0,
                    bytes_per_sec: 0.0,
                    cpu_seconds: None,
                    cpu_percent: None,
                    peak_rss_bytes: None,
                },
            },
        };

        let v = serde_json::to_value(&bench).unwrap();
        let o = v.as_object().unwrap();
        for k in [
            "schema_version",
            "generated_unix_ms",
            "tool_version",
            "git_head",
            "spec_pin",
            "params",
            "results",
        ] {
            assert!(o.contains_key(k), "missing key {k}");
        }
    }
}
