//! Certificate chains, revocation notices and invite links, all given as text.
#![no_main]
use kith_core::membership::{CertChain, Invite, Revocation};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = CertChain::from_hex(text);
        let _ = Revocation::from_hex(text);
        let _ = Invite::parse(text);
    }
});
