import Foundation
import Network

private enum TestFailure: Error { case failed(String) }
private func check(_ value: Bool, _ message: String) throws {
    if !value { throw TestFailure.failed(message) }
}
private func rejects(_ message: String, _ operation: () throws -> Void) throws {
    do { try operation() } catch { return }
    throw TestFailure.failed(message)
}
private func outgoing(_ result: Handshake.Result) throws -> BridgeFrame {
    switch result {
    case .send(let frame), .paired(.some(let frame)), .authenticated(.some(let frame)): return frame
    default: throw TestFailure.failed("expected a reply")
    }
}
private let exporter = Data(repeating: 42, count: 32)
private let alternate = Data(repeating: 43, count: 32)

private func exchange(_ pin: String = "0042", binding: Data = exporter) throws -> (Handshake, Handshake, BridgeFrame) {
    let (receiver, hello) = try Handshake.pairingReceiver(exporter: binding, pin: pin)
    let sender = Handshake.sender(exporter: exporter)
    let reply = try outgoing(sender.receive(hello, takePIN: { "0042" }))
    return (sender, receiver, try outgoing(receiver.receive(reply)))
}

private func testPairing() throws {
    try check(validPIN("0000") && validPIN("0042") && !validPIN("１２３４") && !validPIN("1234 "), "PIN format")
    var gate = PairingWindow(pin: "0042", now: 0)
    for _ in 1...3 { try check(try gate.takeAttempt(now: 119.9) == "0042", "attempt allowed") }
    try rejects("fourth attempt") { _ = try gate.takeAttempt(now: 119.9) }
    var expired = PairingWindow(pin: "0042", now: 0)
    try rejects("expiry") { _ = try expired.takeAttempt(now: 120) }

    let (sender, receiver, proof) = try exchange()
    var saved: Data?
    let accepted = try outgoing(sender.receive(proof, save: { saved = $0 }))
    let result = try receiver.receive(accepted, save: { try check($0 == saved && $0.count == 32, "same persisted key") })
    guard case .paired(nil) = result, let key = saved else { throw TestFailure.failed("paired") }
    try rejects("pairing connection cannot start") { _ = try sender.receive(.init(.start), key: key) }
    try rejects("pairing connection cannot receive PCM") { _ = try receiver.receive(.init(.audio, Data([0, 0]))) }
    for (pin, binding) in [("0043", exporter), ("0042", alternate)] {
        let (sender, _, proof) = try exchange(pin, binding: binding)
        var saved = false
        try rejects("wrong PIN or exporter") { _ = try sender.receive(proof, save: { _ in saved = true }) }
        try check(!saved, "bad proofs must not save")
    }
    let (failing, _, pendingProof) = try exchange()
    try rejects("sender storage failure") { _ = try failing.receive(pendingProof, save: { _ in throw BridgeError.storage }) }
    try rejects("failed attempt is nonreusable") { _ = try failing.receive(pendingProof, save: { _ in }) }
    let (sender2, receiver2, proof2) = try exchange()
    let accepted2 = try outgoing(sender2.receive(proof2, save: { _ in }))
    try rejects("receiver storage failure") { _ = try receiver2.receive(accepted2, save: { _ in throw BridgeError.storage }) }
    let (fakeSender, fakeReceiver, fakeProof) = try exchange()
    let realAck = try outgoing(fakeSender.receive(fakeProof, save: { _ in }))
    var forged = realAck.payload
    forged[forged.startIndex] ^= 1
    try rejects("forged pairing receipt") { _ = try fakeReceiver.receive(.init(.pairAccepted, forged), save: { _ in }) }
    let (sender3, _, proof3) = try exchange()
    try rejects("cancelled or expired in-flight attempt") { _ = try sender3.receive(proof3, save: { _ in throw BridgeError.pairingUnavailable }) }
}

private func testReconnection() throws {
    let key = Data(repeating: 123, count: 32)
    let (receiver, hello) = Handshake.knownReceiver(exporter: exporter, key: key)
    let sender = Handshake.sender(exporter: exporter)
    let header = BridgeFrame(.header, Data([128, 187, 0, 0]))
    try rejects("start before auth") { _ = try sender.receive(.init(.start), key: key) }
    try rejects("header before auth") { _ = try receiver.receive(header) }
    try rejects("receiver proof replay on another channel") { _ = try Handshake.sender(exporter: alternate).receive(hello, key: key) }
    try rejects("revoked peer proof") { _ = try Handshake.sender(exporter: exporter).receive(hello) }
    try rejects("forged proof") { _ = try sender.receive(.init(.authHello, Data(repeating: 0, count: 32)), key: key) }
    try rejects("forged sender confirmation") { _ = try receiver.receive(.init(.authAccepted, hello.payload)) }
    let ack = try outgoing(sender.receive(hello, key: key))
    let (otherReceiver, _) = Handshake.knownReceiver(exporter: alternate, key: key)
    try rejects("server proof replay on another channel") { _ = try otherReceiver.receive(ack) }
    guard case .authenticated(nil) = try receiver.receive(ack),
          case .application(let start) = try sender.receive(.init(.start)), start.kind == .start,
          case .application(let output) = try receiver.receive(header), output == header else {
        throw TestFailure.failed("authenticated controls and audio")
    }
    try rejects("wrong direction") { _ = try sender.receive(header) }
    try rejects("new pairing on authenticated connection") { _ = try sender.receive(.init(.pairHello, hello.payload)) }
}

private func testFramesAndStorage() throws {
    let frames = [BridgeFrame(.start), BridgeFrame(.audio, Data([0, 1])), BridgeFrame(.pause), BridgeFrame(.paused)]
    let bytes = frames.reduce(into: Data()) { $0.append($1.encode()) }
    for split in 0...bytes.count {
        var decoder = BridgeDecoder()
        let decoded = try decoder.append(Data(bytes.prefix(split))) + decoder.append(Data(bytes.dropFirst(split)))
        try check(decoded == frames, "fragmented/coalesced frames")
    }
    for bad in [[255, 0, 0, 0, 0], [65, 0, 1, 0, 1], [65, 0, 0, 0, 1], [83, 0, 0, 0, 1]] as [[UInt8]] {
        try rejects("malformed frame") { var decoder = BridgeDecoder(); _ = try decoder.append(Data(bad)) }
    }
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("micbridge-test-\(UUID())")
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = PairingStore(role: "sender", directory: directory)
    let file = directory.appendingPathComponent("sender.key")
    try check(try store.load() == nil, "missing file")
    let key = Data(repeating: 99, count: 32)
    try store.save(key)
    try check(try PairingStore(role: "sender", directory: directory).load() == key, "persisted load")
    try check(try PairingStore(role: "receiver", directory: directory).load() == nil, "separate roles")
    for (url, expected) in [(directory, 0o700), (file, 0o600)] {
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        try check((attrs[.posixPermissions] as? NSNumber)?.intValue == expected, "private permissions")
    }
    chmod(file.path, 0o644)
    try rejects("insecure key rejected") { _ = try store.load() }
    try store.remove()
    try check(try store.load() == nil, "revocation persisted")
    try FileManager.default.createSymbolicLink(atPath: file.path, withDestinationPath: "/dev/null")
    try rejects("symlink rejected") { _ = try store.load() }
}

// Exercise the same listener, identity, TLS exporter, framing, and callbacks
// as the apps, without touching the microphone, BlackHole, Bonjour or user keys.
private final class Loopback {
    let queue = DispatchQueue(label: "micbridge.tests")
    let done = DispatchSemaphore(value: 0)
    var failure: Error?
    var listener: NWListener?
    var client: BridgeConnection?
    var server: BridgeConnection?
    var probe: NWConnection?
    var staleCallbacks = 0
    var key: Data?
    var bind: Data?
    var acceptedAudio = false
    var phase = 0
    var ending = false

    func run() throws {
        let parameters = try secureParameters(identity: makeTLSIdentity(), queue: queue)
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        self.listener = listener
        listener.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            if case .ready = state { self.connect() }
            if case .failed(let error) = state { self.finish(error) }
        }
        listener.newConnectionHandler = { [weak self] conn in
            guard let self else { conn.cancel(); return }
            self.accept(conn)
        }
        listener.start(queue: queue)
        if done.wait(timeout: .now() + 12) != .success { throw TestFailure.failed("loopback timeout, phase \(queue.sync { phase })") }
        if let failure { throw failure }
    }

    func finish(_ error: Error? = nil) {
        guard !ending else { return }
        ending = true
        failure = error
        listener?.cancel()
        client?.close()
        server?.close()
        probe?.cancel()
        done.signal()
    }

    func connect() {
        guard let port = listener?.port else { finish(TestFailure.failed("no bound port")); return }
        let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: port)
        if phase == 2 {
            // An incompatible client must never make it into the app protocol.
            let probe = NWConnection(to: endpoint, using: .tcp)
            self.probe = probe
            probe.stateUpdateHandler = { [weak probe] state in
                guard let probe else { return }
                if case .ready = state {
                    probe.send(content: Data("legacy client\n".utf8), completion: .idempotent)
                }
                if case .failed = state { probe.cancel() }
            }
            probe.start(queue: queue)
            return
        }
        let conn = BridgeConnection(NWConnection(to: endpoint, using: secureParameters(queue: queue)))
        client = conn
        conn.start(on: queue, ready: { [weak self, weak conn] exporter in
            guard let self else { return }
            let (auth, hello) = try self.key.map { Handshake.knownReceiver(exporter: exporter, key: $0) }
                ?? Handshake.pairingReceiver(exporter: exporter, pin: "0042")
            conn?.handshake = auth
            conn?.send(hello)
        }, frame: { [weak self, weak conn] frame in
            guard let self, let conn, let auth = conn.handshake else { throw TestFailure.failed("missing client handshake") }
            switch try auth.receive(frame, save: { try check($0 == self.key, "loopback key confirmation") }) {
            case .send(let reply): conn.send(reply)
            case .paired:
                self.phase = 1
                conn.send(.init(.pause)) { self.staleCallbacks += 1 }
                conn.close()
            case .authenticated: conn.send(.init(.start))
            case .application(let frame):
                try check(frame == BridgeFrame(.audio, Data([1, 2])), "authenticated loopback audio")
                self.acceptedAudio = true
                self.phase = 2
                conn.close()
            }
        }, closed: { [weak self] error in
            guard let self else { return }
            if !self.ending, let error { self.finish(error) }
        })
    }

    func accept(_ connection: NWConnection) {
        let conn = BridgeConnection(connection)
        server = conn
        conn.start(on: queue, ready: { [weak self, weak conn] exporter in
            guard let self else { return }
            if self.phase == 2 {
                self.finish(TestFailure.failed("plaintext entered the application protocol"))
                return
            }
            try check(self.bind != exporter, "distinct connection exporters")
            self.bind = exporter
            conn?.handshake = .sender(exporter: exporter)
        }, frame: { [weak self, weak conn] frame in
            guard let self, let conn, let auth = conn.handshake else { throw TestFailure.failed("missing server handshake") }
            let result = try auth.receive(frame, key: self.key, takePIN: { "0042" }, save: { self.key = $0 })
            if case .application(let action) = result {
                try check(self.phase == 1 && action.kind == .start, "only authenticated start")
                conn.send(.init(.audio, Data([1, 2])))
            } else { conn.send(try outgoing(result)) }
        }, closed: { [weak self] error in
            guard let self, !self.ending else { return }
            if self.phase == 2, self.probe != nil {
                let valid = self.acceptedAudio && self.staleCallbacks == 0
                self.finish(valid ? nil : TestFailure.failed("missing audio or stale callback"))
            } else if let error { self.finish(error) }
            else { self.connect() }
        })
    }
}

@main
struct SecureProtocolTests {
    static func main() throws {
        try testPairing()
        try testReconnection()
        try testFramesAndStorage()
        try Loopback().run()
        print("PASS: pairing, auth, framing, key storage and real TLS 1.3 loopback")
    }
}
