// Hand-written Swift conveniences on top of the generated `Kith.swift`.
// Keep logic in Rust; only add Swift ergonomics here.
import Foundation

public extension KithClient {
    /// Create an object from a UTF-8 string payload.
    func create(type: String, text: String) throws -> ChangeInfo {
        try create(objectType: type, payload: Data(text.utf8))
    }
}
