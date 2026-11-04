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
/// same time are reached, and message bodies are not encrypted yet.
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
            send(try session.hello())
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

    /// Close the connection.
    public func stop() {
        task.cancel(with: .normalClosure, reason: nil)
    }

    private func send(_ data: Data) {
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
                        for reply in output.replies { self.send(reply) }
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
