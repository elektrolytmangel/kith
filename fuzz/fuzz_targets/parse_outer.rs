//! The outer relay body parser: everything a peer or the relay can send.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = kith_client::fuzz_api::parse_outer(data);
});
