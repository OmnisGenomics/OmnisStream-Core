#![forbid(unsafe_code)]

//! Unstable OmnisStream backend extension APIs.
//!
//! This crate is intentionally tiny and **not** considered part of the stable OmnisStream API
//! surface yet. It exists so external projects (e.g. enterprise backends) can implement a backend
//! without depending on `omnisstream` internals.

use std::io;

/// Backend interface used by OmnisStream ingest to read positional byte ranges.
///
/// # Stability
/// This API is **unstable** and may change across minor/patch releases until explicitly stabilized.
pub trait IngestBackend: Clone + Send + Sync + 'static {
    /// Reads exactly `buf.len()` bytes starting at `offset` into `buf`.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
}
