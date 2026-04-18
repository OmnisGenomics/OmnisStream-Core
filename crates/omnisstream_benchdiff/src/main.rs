use std::path::{Path, PathBuf};

use anyhow::Context as _;
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

    #[serde(default)]
    relaxed_durability: bool,

    #[serde(default)]
    bench_decompression: bool,

    #[serde(default)]
    input_file_blake3_256: Option<String>,

    #[serde(default)]
    compression: bool,

    #[serde(default)]
    compression_level: Option<i32>,

    #[serde(default)]
    compression_frame_size_bytes: Option<u32>,

    #[serde(default)]
    group_commit: bool,

    #[serde(default)]
    group_commit_max_ops: Option<usize>,

    #[serde(default)]
    group_commit_window_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct BenchResultsJson {
    ingest: BytesScenarioJson,
    verify: BytesScenarioJson,
    #[serde(default)]
    decompress: Option<BytesScenarioJson>,
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
        if self.base == 0.0 {
            return matches!(self.better, Better::Lower) && self.new > 0.0;
        }

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
    if let Some(threshold) = args.threshold_percent {
        validate_threshold_percent(threshold)?;
    }

    let base = load_bench_json(&args.base, "base")?;
    let new = load_bench_json(&args.new, "new")?;

    if base.schema_version != 1 || new.schema_version != 1 {
        anyhow::bail!(
            "unsupported schema_version (base={}, new={})",
            base.schema_version,
            new.schema_version
        );
    }

    ensure_same_params(&base.params, &new.params)?;

    let rows = diff_rows(base.results, new.results, base.params.bench_decompression)?;

    print_table(&rows);

    if let Some(threshold) = args.threshold_percent {
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

fn load_bench_json(path: &Path, side: &str) -> anyhow::Result<BenchJson> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading {side} benchmark JSON {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding {side} benchmark JSON {}", path.display()))
}

fn validate_threshold_percent(threshold: f64) -> anyhow::Result<()> {
    if !threshold.is_finite() || threshold < 0.0 {
        anyhow::bail!("threshold_percent must be finite and >= 0");
    }

    Ok(())
}

fn ensure_same_params(base: &BenchParamsJson, new: &BenchParamsJson) -> anyhow::Result<()> {
    macro_rules! ensure_same_param {
        ($field:ident) => {
            if base.$field != new.$field {
                anyhow::bail!(
                    "bench param {} differs (base={:?}, new={:?}); refuse to diff different scenarios",
                    stringify!($field),
                    &base.$field,
                    &new.$field
                );
            }
        };
    }

    ensure_same_param!(preset);
    ensure_same_param!(file_size_bytes);
    ensure_same_param!(part_size_bytes);
    ensure_same_param!(range_len_bytes);
    ensure_same_param!(range_ops);
    ensure_same_param!(seed);
    ensure_same_param!(relaxed_durability);
    ensure_same_param!(bench_decompression);
    ensure_same_param!(input_file_blake3_256);
    ensure_same_param!(compression);
    ensure_same_param!(compression_level);
    ensure_same_param!(compression_frame_size_bytes);
    ensure_same_param!(group_commit);
    ensure_same_param!(group_commit_max_ops);
    ensure_same_param!(group_commit_window_ms);

    Ok(())
}

fn diff_rows(
    base: BenchResultsJson,
    new: BenchResultsJson,
    bench_decompression: bool,
) -> anyhow::Result<Vec<MetricRow>> {
    if !base.results_ok() {
        anyhow::bail!("base bench contains failed scenario(s)");
    }
    if !new.results_ok() {
        anyhow::bail!("new bench contains failed scenario(s)");
    }

    let mut rows = Vec::new();
    rows.extend(bytes_rows("ingest", base.ingest, new.ingest)?);
    rows.extend(bytes_rows("verify", base.verify, new.verify)?);

    match (base.decompress, new.decompress) {
        (Some(base_decompress), Some(new_decompress)) => {
            rows.extend(bytes_rows("decompress", base_decompress, new_decompress)?);
        }
        (None, None) if bench_decompression => {
            anyhow::bail!("bench_decompression is true but decompress result is missing");
        }
        (None, None) => {}
        _ => {
            anyhow::bail!("decompress result presence differs; refuse to diff different scenarios");
        }
    }

    rows.extend(range_rows(
        "range_reads",
        base.range_reads,
        new.range_reads,
    )?);
    Ok(rows)
}

impl BenchResultsJson {
    fn results_ok(&self) -> bool {
        self.ingest.ok
            && self.verify.ok
            && self.range_reads.ok
            && self.decompress.as_ref().is_none_or(|scenario| scenario.ok)
    }
}

fn bytes_rows(
    prefix: &'static str,
    base: BytesScenarioJson,
    new: BytesScenarioJson,
) -> anyhow::Result<Vec<MetricRow>> {
    let mut out = Vec::new();
    push_row(
        &mut out,
        concat_key(prefix, "bytes_per_sec"),
        Better::Higher,
        base.bytes_per_sec,
        new.bytes_per_sec,
    )?;
    push_row(
        &mut out,
        concat_key(prefix, "wall_seconds"),
        Better::Lower,
        base.wall_seconds,
        new.wall_seconds,
    )?;
    push_optional_row(
        &mut out,
        prefix,
        "cpu_seconds",
        Better::Lower,
        base.cpu_seconds,
        new.cpu_seconds,
    )?;
    push_optional_row(
        &mut out,
        prefix,
        "cpu_percent",
        Better::Lower,
        base.cpu_percent,
        new.cpu_percent,
    )?;
    push_optional_row(
        &mut out,
        prefix,
        "peak_rss_bytes",
        Better::Lower,
        base.peak_rss_bytes.map(|v| v as f64),
        new.peak_rss_bytes.map(|v| v as f64),
    )?;
    Ok(out)
}

fn range_rows(
    prefix: &'static str,
    base: RangeScenarioJson,
    new: RangeScenarioJson,
) -> anyhow::Result<Vec<MetricRow>> {
    let mut out = Vec::new();
    push_row(
        &mut out,
        concat_key(prefix, "ops_per_sec"),
        Better::Higher,
        base.ops_per_sec,
        new.ops_per_sec,
    )?;
    push_row(
        &mut out,
        concat_key(prefix, "bytes_per_sec"),
        Better::Higher,
        base.bytes_per_sec,
        new.bytes_per_sec,
    )?;
    push_row(
        &mut out,
        concat_key(prefix, "wall_seconds"),
        Better::Lower,
        base.wall_seconds,
        new.wall_seconds,
    )?;
    push_optional_row(
        &mut out,
        prefix,
        "cpu_seconds",
        Better::Lower,
        base.cpu_seconds,
        new.cpu_seconds,
    )?;
    push_optional_row(
        &mut out,
        prefix,
        "cpu_percent",
        Better::Lower,
        base.cpu_percent,
        new.cpu_percent,
    )?;
    push_optional_row(
        &mut out,
        prefix,
        "peak_rss_bytes",
        Better::Lower,
        base.peak_rss_bytes.map(|v| v as f64),
        new.peak_rss_bytes.map(|v| v as f64),
    )?;
    Ok(out)
}

fn push_row(
    out: &mut Vec<MetricRow>,
    key: &'static str,
    better: Better,
    base: f64,
    new: f64,
) -> anyhow::Result<()> {
    validate_metric_value(key, "base", base)?;
    validate_metric_value(key, "new", new)?;
    out.push(MetricRow {
        key,
        better,
        base,
        new,
    });
    Ok(())
}

fn validate_metric_value(key: &'static str, side: &str, value: f64) -> anyhow::Result<()> {
    if !value.is_finite() || value < 0.0 {
        anyhow::bail!("{key} {side} value must be finite and >= 0");
    }
    Ok(())
}

fn push_optional_row(
    out: &mut Vec<MetricRow>,
    prefix: &'static str,
    metric: &'static str,
    better: Better,
    base: Option<f64>,
    new: Option<f64>,
) -> anyhow::Result<()> {
    let key = concat_key(prefix, metric);
    match (base, new) {
        (Some(base), Some(new)) => push_row(out, key, better, base, new)?,
        (None, None) => {}
        _ => anyhow::bail!("{key} presence differs; refuse to diff different result shapes"),
    }

    Ok(())
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

        ("decompress", "bytes_per_sec") => "decompress.bytes_per_sec",
        ("decompress", "wall_seconds") => "decompress.wall_seconds",
        ("decompress", "cpu_seconds") => "decompress.cpu_seconds",
        ("decompress", "cpu_percent") => "decompress.cpu_percent",
        ("decompress", "peak_rss_bytes") => "decompress.peak_rss_bytes",

        ("range_reads", "ops_per_sec") => "range_reads.ops_per_sec",
        ("range_reads", "bytes_per_sec") => "range_reads.bytes_per_sec",
        ("range_reads", "wall_seconds") => "range_reads.wall_seconds",
        ("range_reads", "cpu_seconds") => "range_reads.cpu_seconds",
        ("range_reads", "cpu_percent") => "range_reads.cpu_percent",
        ("range_reads", "peak_rss_bytes") => "range_reads.peak_rss_bytes",
        _ => unreachable!("unknown bench metric key: {prefix}.{metric}"),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> BenchParamsJson {
        BenchParamsJson {
            preset: "default".to_string(),
            file_size_bytes: 1024,
            part_size_bytes: 256,
            range_len_bytes: 64,
            range_ops: 8,
            seed: 42,
            relaxed_durability: false,
            bench_decompression: false,
            input_file_blake3_256: None,
            compression: false,
            compression_level: None,
            compression_frame_size_bytes: None,
            group_commit: false,
            group_commit_max_ops: None,
            group_commit_window_ms: None,
        }
    }

    fn bytes(ok: bool, bytes_per_sec: f64, wall_seconds: f64) -> BytesScenarioJson {
        BytesScenarioJson {
            ok,
            wall_seconds,
            bytes_per_sec,
            cpu_seconds: None,
            cpu_percent: None,
            peak_rss_bytes: None,
        }
    }

    fn range(
        ok: bool,
        ops_per_sec: f64,
        bytes_per_sec: f64,
        wall_seconds: f64,
    ) -> RangeScenarioJson {
        RangeScenarioJson {
            ok,
            wall_seconds,
            ops_per_sec,
            bytes_per_sec,
            cpu_seconds: None,
            cpu_percent: None,
            peak_rss_bytes: None,
        }
    }

    fn results(decompress: Option<BytesScenarioJson>) -> BenchResultsJson {
        BenchResultsJson {
            ingest: bytes(true, 100.0, 1.0),
            verify: bytes(true, 200.0, 0.5),
            decompress,
            range_reads: range(true, 10.0, 300.0, 0.25),
        }
    }

    #[test]
    fn diff_rows_include_decompress_when_present() {
        let rows = diff_rows(
            results(Some(bytes(true, 100.0, 1.0))),
            results(Some(bytes(true, 80.0, 1.25))),
            true,
        )
        .unwrap();
        let keys = rows.iter().map(|row| row.key).collect::<Vec<_>>();

        assert!(keys.contains(&"decompress.bytes_per_sec"), "{keys:?}");
        assert!(keys.contains(&"decompress.wall_seconds"), "{keys:?}");
        assert_eq!(
            rows.iter()
                .find(|row| row.key == "decompress.bytes_per_sec")
                .and_then(|row| row.delta_pct()),
            Some(-20.0)
        );
    }

    #[test]
    fn diff_rows_reject_missing_decompress_when_enabled() {
        let err = diff_rows(results(None), results(None), true).unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("bench_decompression is true"), "{msg}");
    }

    #[test]
    fn diff_rows_reject_decompress_presence_mismatch() {
        let err =
            diff_rows(results(Some(bytes(true, 100.0, 1.0))), results(None), true).unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("decompress result presence differs"), "{msg}");
    }

    #[test]
    fn diff_rows_reject_optional_bytes_metric_presence_mismatch() {
        let mut base = results(None);
        let new = results(None);
        base.ingest.cpu_seconds = Some(1.0);

        let err = diff_rows(base, new, false).unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("ingest.cpu_seconds presence differs"), "{msg}");
    }

    #[test]
    fn diff_rows_reject_optional_range_metric_presence_mismatch() {
        let base = results(None);
        let mut new = results(None);
        new.range_reads.peak_rss_bytes = Some(1024);

        let err = diff_rows(base, new, false).unwrap_err();
        let msg = err.to_string();

        assert!(
            msg.contains("range_reads.peak_rss_bytes presence differs"),
            "{msg}"
        );
    }

    #[test]
    fn diff_rows_reject_negative_required_metric() {
        let mut base = results(None);
        let new = results(None);
        base.ingest.bytes_per_sec = -1.0;

        let err = diff_rows(base, new, false).unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("ingest.bytes_per_sec base value"), "{msg}");
        assert!(msg.contains("finite and >= 0"), "{msg}");
    }

    #[test]
    fn diff_rows_reject_non_finite_optional_metric() {
        let mut base = results(None);
        let mut new = results(None);
        base.verify.cpu_percent = Some(50.0);
        new.verify.cpu_percent = Some(f64::INFINITY);

        let err = diff_rows(base, new, false).unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("verify.cpu_percent new value"), "{msg}");
        assert!(msg.contains("finite and >= 0"), "{msg}");
    }

    #[test]
    #[should_panic(expected = "unknown bench metric key")]
    fn concat_key_rejects_unknown_metric() {
        let _ = concat_key("ingest", "not_a_metric");
    }

    #[test]
    fn validate_threshold_percent_accepts_finite_non_negative_values() {
        validate_threshold_percent(0.0).unwrap();
        validate_threshold_percent(5.0).unwrap();
    }

    #[test]
    fn validate_threshold_percent_rejects_negative_and_non_finite_values() {
        for threshold in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let err = validate_threshold_percent(threshold).unwrap_err();
            let msg = err.to_string();

            assert!(msg.contains("finite and >= 0"), "{msg}");
        }
    }

    #[test]
    fn lower_metric_regresses_from_zero_baseline() {
        let row = MetricRow {
            key: "ingest.wall_seconds",
            better: Better::Lower,
            base: 0.0,
            new: 0.1,
        };

        assert!(row.is_regression(100.0));
        assert_eq!(row.delta_pct(), None);
    }

    #[test]
    fn higher_metric_does_not_regress_from_zero_baseline() {
        let row = MetricRow {
            key: "ingest.bytes_per_sec",
            better: Better::Higher,
            base: 0.0,
            new: 100.0,
        };

        assert!(!row.is_regression(0.0));
        assert_eq!(row.delta_pct(), None);
    }

    #[test]
    fn ensure_same_params_reports_changed_field() {
        let base = params();
        let mut new = params();
        new.group_commit_window_ms = Some(25);

        let err = ensure_same_params(&base, &new).unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("group_commit_window_ms"), "{msg}");
        assert!(msg.contains("refuse to diff different scenarios"), "{msg}");
    }

    #[test]
    fn load_bench_json_read_error_includes_path_and_side() {
        let path = std::env::temp_dir().join(format!(
            "omnisstream_benchdiff_missing_{}_base.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let err = load_bench_json(&path, "base").unwrap_err();
        let msg = format!("{err:#}");

        assert!(msg.contains("reading base benchmark JSON"), "{msg}");
        assert!(msg.contains(&path.display().to_string()), "{msg}");
    }

    #[test]
    fn load_bench_json_decode_error_includes_path_and_side() {
        let path = std::env::temp_dir().join(format!(
            "omnisstream_benchdiff_invalid_{}_new.json",
            std::process::id()
        ));
        std::fs::write(&path, b"{").unwrap();

        let err = load_bench_json(&path, "new").unwrap_err();
        let msg = format!("{err:#}");

        assert!(msg.contains("decoding new benchmark JSON"), "{msg}");
        assert!(msg.contains(&path.display().to_string()), "{msg}");

        std::fs::remove_file(path).unwrap();
    }
}
