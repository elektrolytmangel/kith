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

    /// req: REQ-SYNC-004
    /// req: REQ-ENC-001
    /// req: REQ-INV-001
    func testRelaySessionProducesFrames() throws {
        let client = KithClient()
        let org = try client.createOrg()
        XCTAssertTrue(client.isMember(org: org))
        XCTAssertTrue(client.isAdmin(org: org))
        XCTAssertEqual(try client.groupMembers(org: org), [client.deviceId()])
        let session = client.relaySession(org: org)
        XCTAssertFalse(try session.hello().isEmpty)
        let change = try client.create(type: "note", text: "hello")
        XCTAssertFalse(try session.broadcast(changeId: change.changeId).isEmpty)
        XCTAssertFalse(try session.rotateKey().isEmpty)
        XCTAssertEqual(try session.roleOf(device: client.deviceId()), "admin")
        XCTAssertFalse(try session.setWriteRule(objectType: "config", role: "admin").isEmpty)
        XCTAssertThrowsError(try session.setRole(device: client.deviceId(), role: "boss"))
        XCTAssertThrowsError(try session.receive(frame: Data("not a frame".utf8)))
        // An invite another device can claim.
        let link = try client.createInvite(org: org, relay: "wss://relay.example/v1/ws", ttlSeconds: 600)
        let info = try parseInvite(link: link)
        XCTAssertEqual(info.org, org)
        let newcomer = KithClient()
        XCTAssertThrowsError(try newcomer.relaySession(org: org).broadcast(changeId: change.changeId))
        let claim = try newcomer.relaySession(org: info.org).claim(link: link)
        XCTAssertFalse(claim.frame.isEmpty)
        XCTAssertEqual(claim.code.count, 6)
    }

    /// req: REQ-DATA-004
    func testDocuments() throws {
        let client = KithClient()
        let doc = try client.createDocument(objectType: "todo", json: #"{"title":"x"}"#)
        XCTAssertNotNil(try client.updateDocument(objectId: doc.objectId, patch: #"{"done":true}"#))
        XCTAssertNil(try client.updateDocument(objectId: doc.objectId, patch: #"{"done":true}"#))
        let json = try client.documentJson(objectId: doc.objectId)
        let parsed = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        XCTAssertEqual(parsed?["title"] as? String, "x")
        XCTAssertEqual(parsed?["done"] as? Bool, true)
        XCTAssertThrowsError(try client.createDocument(objectType: "todo", json: "[1]"))
    }

    /// req: REQ-PLAT-002
    func testRestoredKeyKeepsDeviceIdentity() throws {
        let first = KithClient()
        let restored = try KithClient.withSecretKey(secretKey: first.secretKey())
        XCTAssertEqual(restored.deviceId(), first.deviceId())
        XCTAssertThrowsError(try KithClient.withSecretKey(secretKey: Data(count: 31)))
    }
}
