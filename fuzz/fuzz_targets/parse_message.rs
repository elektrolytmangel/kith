//! The inner (decrypted) message parser.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = kith_client::fuzz_api::parse_message(data);
});
