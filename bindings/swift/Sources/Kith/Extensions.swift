// Hand-written Swift conveniences on top of the generated `Kith.swift`.
// Keep logic in Rust; only add Swift ergonomics here.
import Foundation

public extension KithClient {
    /// Create an object from a UTF-8 string payload.
    func create(type: String, text: String) throws -> ChangeInfo {
        try create(objectType: type, payload: Data(text.utf8))
    }
}

/// Live sync with one organization over a `URLSessionWebSocketTask`.
///
/// All protocol logic lives in Rust (`RelaySession`); this class only moves
/// binary messages between the socket and the session. Only devices online at the
/// same time are reached; `catchUp()` fetches the rest. Every message is
/// encrypted for the org's MLS group, so the device must be a member:
/// `client.createOrg()` on the first device; others join with an invite
/// (`client.createInvite(...)` on an admin, `claim(link)` on the new device, and
/// `acceptClaim(device)` on the admin's `.inviteClaimed`).
///
///     let conn = RelayConnection(client: client, url: relayURL, org: "my-org",
///                                onEvent: { event in ... })
///     conn.start()
///     let change = try client.create(type: "note", text: "hi")
///     conn.broadcast(change)
public final class RelayConnection {
    private let session: RelaySession
    private let task: URLSessionWebSocketTask
    private let onEvent: (RelayEvent) -> Void
    private let onClose: (Error?) -> Void
    /// Frames sent before the relay's challenge was answered; nil once it was.
    private var outbox: [Data]? = []
    private let lock = NSLock()

    /// - Parameters:
    ///   - url: the relay's WebSocket endpoint, e.g. `wss://relay.example.com/v1/ws`.
    ///   - onEvent: called for each event (`received`, `rejected`, `presence`, ...), on a background queue.
    ///   - onClose: called when the connection ends (with the error, if it failed).
    public init(
        client: KithClient,
        url: URL,
        org: String,
        onEvent: @escaping (RelayEvent) -> Void,
        onClose: @escaping (Error?) -> Void = { _ in }
    ) {
        self.session = client.relaySession(org: org)
        self.task = URLSession.shared.webSocketTask(with: url)
        self.onEvent = onEvent
        self.onClose = onClose
    }

    /// Open the connection, authenticate and join the organization.
    public func start() {
        task.resume()
        do {
            sendNow(try session.hello())
        } catch {
            onClose(error)
            return
        }
        listen()
    }

    /// Tell the other online devices about a change made with `create`/`edit`.
    public func broadcast(_ change: ChangeInfo) {
        do {
            send(try session.broadcast(changeId: change.changeId))
        } catch {
            onClose(error)
        }
    }

    /// Ask one online peer for the changes this device lacks and offer it ours. Call it
    /// once a `.presence` event shows another device; use it on a new device to download
    /// the history. Results arrive as `.syncCompared` (both counts 0: in sync) and `.syncReceived` events.
    public func catchUp() {
        do {
            for frame in try session.catchUp() { send(frame) }
        } catch {
            onClose(error)
        }
    }

    /// Claim an invite link (connect to its relay and org first, see `parseInvite`).
    /// The admin's answer arrives as `.claimCode` (show its code); `.joined` follows
    /// once the admin accepts.
    public func claim(_ link: String) throws {
        send(try session.claim(link: link))
    }

    /// Admit the device of an `.inviteClaimed` event.
    public func acceptClaim(_ deviceId: String) throws {
        for frame in try session.acceptClaim(device: deviceId) { send(frame) }
    }

    /// Refuse the claim of an `.inviteClaimed` event; the invite stays valid.
    public func rejectClaim(_ deviceId: String) {
        session.rejectClaim(device: deviceId)
    }

    /// Make a member an admin (only the org's creator can).
    public func grantAdmin(_ deviceId: String) throws {
        for frame in try session.grantAdmin(device: deviceId) { send(frame) }
    }

    /// Remove a device from the org's group.
    public func removeMember(_ deviceId: String) throws {
        for frame in try session.removeMember(device: deviceId) { send(frame) }
    }

    /// Create read-restricted subgroup `name` with `members` (admins only). Data
    /// created with `client.createIn(scope: "\(org)/\(name)", ...)` only reaches its members.
    public func createSubgroup(_ name: String, members: [String]) throws {
        for frame in try session.createSubgroup(name: name, members: members) { send(frame) }
    }

    /// Replace the members of subgroup `name` (admins only).
    public func setSubgroupMembers(_ name: String, members: [String]) throws {
        for frame in try session.setSubgroupMembers(name: name, members: members) { send(frame) }
    }

    /// Set a member's role: "viewer", "editor" or "admin" (admin only from the
    /// org's creator). Admins only.
    public func setRole(_ deviceId: String, role: String) throws {
        send(try session.setRole(device: deviceId, role: role))
    }

    /// Set the minimum role that may write objects of `objectType`. Admins only.
    public func setWriteRule(_ objectType: String, role: String) throws {
        send(try session.setWriteRule(objectType: objectType, role: role))
    }

    /// Rotate this device's group key; call it periodically (e.g. weekly).
    public func rotateKey() throws {
        send(try session.rotateKey())
    }

    /// Fetch a file's missing chunks from a peer; `.fileChunks` events report progress.
    public func fetchFile(_ objectId: String) throws {
        for frame in try session.fetchFile(objectId: objectId) { send(frame) }
    }

    /// Close the connection.
    public func stop() {
        task.cancel(with: .normalClosure, reason: nil)
    }

    /// Queue until the handshake is done: the relay refuses frames before `auth`.
    private func send(_ data: Data) {
        lock.lock()
        if outbox != nil {
            outbox!.append(data)
            lock.unlock()
            return
        }
        lock.unlock()
        sendNow(data)
    }

    private func sendNow(_ data: Data) {
        task.send(.data(data)) { [weak self] error in
            if let error = error { self?.onClose(error) }
        }
    }

    private func listen() {
        task.receive { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .failure(let error):
                self.onClose(error)
            case .success(let message):
                var frame: Data?
                switch message {
                case .data(let data): frame = data
                case .string(let text): frame = Data(text.utf8)
                @unknown default: frame = nil
                }
                if let frame = frame {
                    do {
                        let output = try self.session.receive(frame: frame)
                        // The first message is the challenge: its replies (auth +
                        // announce) go first, then anything queued meanwhile.
                        self.lock.lock()
                        let queued = self.outbox
                        self.outbox = nil
                        self.lock.unlock()
                        for reply in output.replies { self.sendNow(reply) }
                        for data in queued ?? [] { self.sendNow(data) }
                        if let event = output.event { self.onEvent(event) }
                    } catch {
                        self.onClose(error)
                        return
                    }
                }
                self.listen()
            }
        }
    }
}
