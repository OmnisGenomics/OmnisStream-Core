#[cfg(feature = "compression")]
use std::sync::Mutex;

/// Compression settings for stored part payload bytes.
///
/// Compression is optional and intended to be enabled by higher-level tooling (e.g. benchmarks).
#[derive(Clone, Copy, Debug)]
pub struct CompressionConfig {
    pub zstd_seekable_level: i32,
}

#[cfg(feature = "compression")]
static COMPRESSION_CONFIG: Mutex<Option<CompressionConfig>> = Mutex::new(None);

pub(crate) fn compression_config() -> Option<CompressionConfig> {
    #[cfg(feature = "compression")]
    {
        match COMPRESSION_CONFIG.lock() {
            Ok(g) => *g,
            Err(e) => *e.into_inner(),
        }
    }

    #[cfg(not(feature = "compression"))]
    {
        None
    }
}

pub(crate) fn set_compression_config(config: Option<CompressionConfig>) {
    #[cfg(feature = "compression")]
    {
        match COMPRESSION_CONFIG.lock() {
            Ok(mut g) => {
                *g = config;
            }
            Err(mut e) => {
                **e.get_mut() = config;
            }
        }
    }

    #[cfg(not(feature = "compression"))]
    {
        let _ = config;
    }
}
