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
}
