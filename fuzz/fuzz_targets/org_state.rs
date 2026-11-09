//! The saved org state reader.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = kith_client::fuzz_api::org_state(data);
});
