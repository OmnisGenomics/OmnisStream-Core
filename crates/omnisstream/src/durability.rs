#[cfg(feature = "bench-relaxed-durability")]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "bench-relaxed-durability")]
static RELAXED_DURABILITY: AtomicBool = AtomicBool::new(false);

pub(crate) fn relaxed_durability_enabled() -> bool {
    #[cfg(feature = "bench-relaxed-durability")]
    {
        RELAXED_DURABILITY.load(Ordering::Relaxed)
    }

    #[cfg(not(feature = "bench-relaxed-durability"))]
    {
        false
    }
}

#[cfg(feature = "bench-relaxed-durability")]
pub(crate) fn set_relaxed_durability(enabled: bool) {
    RELAXED_DURABILITY.store(enabled, Ordering::Relaxed);
}

#[cfg(feature = "group-commit")]
use std::sync::Mutex;

/// Configuration for group commit durability mode.
///
/// When enabled, the part store defers durability barriers to a background batcher, and `put_*`
/// calls block until the batch barrier has completed.
#[cfg(feature = "group-commit")]
#[derive(Clone, Copy, Debug)]
pub struct GroupCommitConfig {
    pub max_ops: usize,
    pub window_ms: u64,
}

#[cfg(feature = "group-commit")]
static GROUP_COMMIT_CONFIG: Mutex<Option<GroupCommitConfig>> = Mutex::new(None);

#[cfg(feature = "group-commit")]
pub(crate) fn group_commit_config() -> Option<GroupCommitConfig> {
    match GROUP_COMMIT_CONFIG.lock() {
        Ok(g) => *g,
        Err(e) => *e.into_inner(),
    }
}

#[cfg(feature = "group-commit")]
pub(crate) fn set_group_commit_config(config: Option<GroupCommitConfig>) {
    match GROUP_COMMIT_CONFIG.lock() {
        Ok(mut g) => {
            *g = config;
        }
        Err(mut e) => {
            **e.get_mut() = config;
        }
    }
}
