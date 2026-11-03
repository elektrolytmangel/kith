//! Generates Swift/Kotlin sources from the compiled library.
//! Usage: see scripts/build-swift.sh and scripts/build-android.sh.
fn main() {
    uniffi::uniffi_bindgen_main()
}
