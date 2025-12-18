use std::path::PathBuf;

use clap::Parser;
use serde::Deserialize;

#[derive(Debug, Parser)]
#[command(name = "omnisstream_benchdiff")]
struct Args {
    base: PathBuf,
    new: PathBuf,

    /// Fail if any regression exceeds this percent (e.g. 5.0).
    #[arg(long)]
    threshold_percent: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct BenchJson {
    schema_version: u32,
    params: BenchParamsJson,
    results: BenchResultsJson,
}

#[derive(Debug, Deserialize)]
struct BenchParamsJson {
    preset: String,
    file_size_bytes: u64,
    part_size_bytes: u64,
    range_len_bytes: u64,
    range_ops: u64,
    seed: u64,
}

#[derive(Debug, Deserialize)]
struct BenchResultsJson {
    ingest: BytesScenarioJson,
    verify: BytesScenarioJson,
    range_reads: RangeScenarioJson,
}

#[derive(Debug, Deserialize)]
struct BytesScenarioJson {
    ok: bool,
    wall_seconds: f64,
    bytes_per_sec: f64,
    cpu_seconds: Option<f64>,
    cpu_percent: Option<f64>,
    peak_rss_bytes: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RangeScenarioJson {
    ok: bool,
    wall_seconds: f64,
    ops_per_sec: f64,
    bytes_per_sec: f64,
    cpu_seconds: Option<f64>,
    cpu_percent: Option<f64>,
    peak_rss_bytes: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
enum Better {
    Higher,
    Lower,
}

#[derive(Clone, Copy, Debug)]
struct MetricRow {
    key: &'static str,
    better: Better,
    base: f64,
    new: f64,
}

impl MetricRow {
    fn delta_pct(self) -> Option<f64> {
        if self.base == 0.0 {
            return None;
        }
        Some(((self.new - self.base) / self.base) * 100.0)
    }

    fn is_regression(self, threshold_pct: f64) -> bool {
        let Some(d) = self.delta_pct() else {
            return false;
        };
        match self.better {
            Better::Higher => d < -threshold_pct,
            Better::Lower => d > threshold_pct,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let base: BenchJson = serde_json::from_slice(&std::fs::read(&args.base)?)?;
    let new: BenchJson = serde_json::from_slice(&std::fs::read(&args.new)?)?;

    if base.schema_version != 1 || new.schema_version != 1 {
        anyhow::bail!(
            "unsupported schema_version (base={}, new={})",
            base.schema_version,
            new.schema_version
        );
    }

    if base.params.preset != new.params.preset
        || base.params.file_size_bytes != new.params.file_size_bytes
        || base.params.part_size_bytes != new.params.part_size_bytes
        || base.params.range_len_bytes != new.params.range_len_bytes
        || base.params.range_ops != new.params.range_ops
        || base.params.seed != new.params.seed
    {
        anyhow::bail!("bench params differ; refuse to diff different scenarios");
    }

    if !base.results.ingest.ok || !base.results.verify.ok || !base.results.range_reads.ok {
        anyhow::bail!("base bench contains failed scenario(s)");
    }
    if !new.results.ingest.ok || !new.results.verify.ok || !new.results.range_reads.ok {
        anyhow::bail!("new bench contains failed scenario(s)");
    }

    let mut rows = Vec::new();
    rows.extend(bytes_rows(
        "ingest",
        base.results.ingest,
        new.results.ingest,
    ));
    rows.extend(bytes_rows(
        "verify",
        base.results.verify,
        new.results.verify,
    ));
    rows.extend(range_rows(
        "range_reads",
        base.results.range_reads,
        new.results.range_reads,
    ));

    print_table(&rows);

    if let Some(threshold) = args.threshold_percent {
        if threshold < 0.0 {
            anyhow::bail!("threshold_percent must be >= 0");
        }

        let mut bad = Vec::new();
        for row in rows {
            if row.is_regression(threshold) {
                bad.push(row.key);
            }
        }

        if !bad.is_empty() {
            anyhow::bail!(
                "regression over threshold ({threshold}%): {}",
                bad.join(", ")
            );
        }
    }

    Ok(())
}

fn bytes_rows(
    prefix: &'static str,
    base: BytesScenarioJson,
    new: BytesScenarioJson,
) -> Vec<MetricRow> {
    let mut out = Vec::new();
    out.push(MetricRow {
        key: concat_key(prefix, "bytes_per_sec"),
        better: Better::Higher,
        base: base.bytes_per_sec,
        new: new.bytes_per_sec,
    });
    out.push(MetricRow {
        key: concat_key(prefix, "wall_seconds"),
        better: Better::Lower,
        base: base.wall_seconds,
        new: new.wall_seconds,
    });
    if let (Some(b), Some(n)) = (base.cpu_seconds, new.cpu_seconds) {
        out.push(MetricRow {
            key: concat_key(prefix, "cpu_seconds"),
            better: Better::Lower,
            base: b,
            new: n,
        });
    }
    if let (Some(b), Some(n)) = (base.cpu_percent, new.cpu_percent) {
        out.push(MetricRow {
            key: concat_key(prefix, "cpu_percent"),
            better: Better::Lower,
            base: b,
            new: n,
        });
    }
    if let (Some(b), Some(n)) = (base.peak_rss_bytes, new.peak_rss_bytes) {
        out.push(MetricRow {
            key: concat_key(prefix, "peak_rss_bytes"),
            better: Better::Lower,
            base: b as f64,
            new: n as f64,
        });
    }
    out
}

fn range_rows(
    prefix: &'static str,
    base: RangeScenarioJson,
    new: RangeScenarioJson,
) -> Vec<MetricRow> {
    let mut out = Vec::new();
    out.push(MetricRow {
        key: concat_key(prefix, "ops_per_sec"),
        better: Better::Higher,
        base: base.ops_per_sec,
        new: new.ops_per_sec,
    });
    out.push(MetricRow {
        key: concat_key(prefix, "bytes_per_sec"),
        better: Better::Higher,
        base: base.bytes_per_sec,
        new: new.bytes_per_sec,
    });
    out.push(MetricRow {
        key: concat_key(prefix, "wall_seconds"),
        better: Better::Lower,
        base: base.wall_seconds,
        new: new.wall_seconds,
    });
    if let (Some(b), Some(n)) = (base.cpu_seconds, new.cpu_seconds) {
        out.push(MetricRow {
            key: concat_key(prefix, "cpu_seconds"),
            better: Better::Lower,
            base: b,
            new: n,
        });
    }
    if let (Some(b), Some(n)) = (base.cpu_percent, new.cpu_percent) {
        out.push(MetricRow {
            key: concat_key(prefix, "cpu_percent"),
            better: Better::Lower,
            base: b,
            new: n,
        });
    }
    if let (Some(b), Some(n)) = (base.peak_rss_bytes, new.peak_rss_bytes) {
        out.push(MetricRow {
            key: concat_key(prefix, "peak_rss_bytes"),
            better: Better::Lower,
            base: b as f64,
            new: n as f64,
        });
    }
    out
}

fn concat_key(prefix: &'static str, metric: &'static str) -> &'static str {
    // Keep keys stable as compile-time strings.
    match (prefix, metric) {
        ("ingest", "bytes_per_sec") => "ingest.bytes_per_sec",
        ("ingest", "wall_seconds") => "ingest.wall_seconds",
        ("ingest", "cpu_seconds") => "ingest.cpu_seconds",
        ("ingest", "cpu_percent") => "ingest.cpu_percent",
        ("ingest", "peak_rss_bytes") => "ingest.peak_rss_bytes",

        ("verify", "bytes_per_sec") => "verify.bytes_per_sec",
        ("verify", "wall_seconds") => "verify.wall_seconds",
        ("verify", "cpu_seconds") => "verify.cpu_seconds",
        ("verify", "cpu_percent") => "verify.cpu_percent",
        ("verify", "peak_rss_bytes") => "verify.peak_rss_bytes",

        ("range_reads", "ops_per_sec") => "range_reads.ops_per_sec",
        ("range_reads", "bytes_per_sec") => "range_reads.bytes_per_sec",
        ("range_reads", "wall_seconds") => "range_reads.wall_seconds",
        ("range_reads", "cpu_seconds") => "range_reads.cpu_seconds",
        ("range_reads", "cpu_percent") => "range_reads.cpu_percent",
        ("range_reads", "peak_rss_bytes") => "range_reads.peak_rss_bytes",
        _ => "unknown",
    }
}

fn print_table(rows: &[MetricRow]) {
    println!(
        "{:<28} {:>14} {:>14} {:>10}",
        "metric", "base", "new", "delta%"
    );
    for r in rows {
        let delta = r
            .delta_pct()
            .map(|d| format!("{d:+.2}%"))
            .unwrap_or_else(|| "n/a".to_string());
        println!(
            "{:<28} {:>14.4} {:>14.4} {:>10}",
            r.key, r.base, r.new, delta
        );
    }
}
