//! Policy ops: written by org members, validated by every device.
#![no_main]
use kith_core::policy::PolicyOp;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(op) = PolicyOp::decode(data) {
        // What decodes must encode again to something that decodes the same.
        let again = PolicyOp::decode(&op.encode()).expect("re-encoded op decodes");
        assert_eq!(again, op);
    }
});
