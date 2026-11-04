import XCTest
@testable import Kith

final class KithTests: XCTestCase {
    /// req: REQ-PLAT-002
    func testCreateAndHistory() throws {
        let client = KithClient()
        let change = try client.create(type: "note", text: "hello")
        XCTAssertEqual(try client.history(objectId: change.objectId).count, 1)
        XCTAssertFalse(kithVersion().isEmpty)
    }

    /// req: REQ-STORE-001
    func testOpenPersistsDataAndIdentity() throws {
        let path = NSTemporaryDirectory() + "kith-\(UUID().uuidString).db"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let key = generateSecretKey()
        var objectId = ""
        var deviceId = ""
        do {
            let first = try KithClient.open(dbPath: path, secretKey: key)
            objectId = try first.create(type: "note", text: "hello").objectId
            deviceId = first.deviceId()
        }
        let second = try KithClient.open(dbPath: path, secretKey: key)
        XCTAssertEqual(second.deviceId(), deviceId)
        XCTAssertEqual(try second.history(objectId: objectId).count, 1)
    }

    /// req: REQ-PLAT-002
    func testRestoredKeyKeepsDeviceIdentity() throws {
        let first = KithClient()
        let restored = try KithClient.withSecretKey(secretKey: first.secretKey())
        XCTAssertEqual(restored.deviceId(), first.deviceId())
        XCTAssertThrowsError(try KithClient.withSecretKey(secretKey: Data(count: 31)))
    }
}
