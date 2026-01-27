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
