//! Compaction snapshots, which any admin can write into an object's history.
#![no_main]
use kith_core::snapshot::Snapshot;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(snapshot) = Snapshot::decode(data) {
        assert_eq!(Snapshot::decode(&snapshot.encode()), Some(snapshot));
    }
});
