// Hand-written Kotlin conveniences on top of the generated kith_ffi.kt.
// Keep logic in Rust; only add Kotlin ergonomics here.
package dev.kith

/** Create an object from a UTF-8 string payload. */
fun KithClient.create(type: String, text: String): ChangeInfo =
    create(type, text.toByteArray(Charsets.UTF_8))
