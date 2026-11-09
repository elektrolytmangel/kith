//! The signed change codec: what the store and the wire carry.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(change) = kith_store::codec::decode_change(data) {
        // Decoded is not valid: verification must refuse or accept without panicking.
        let _ = change.verify();
        let _ = kith_store::codec::encode_change(&change);
    }
});
