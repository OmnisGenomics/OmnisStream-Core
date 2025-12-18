#![allow(clippy::derive_partial_eq_without_eq)]

pub mod omnisstream {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/omnisstream.v1.rs"));
    }
}
