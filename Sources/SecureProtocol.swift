import CryptoKit
import Foundation
import Network
import Security

let serviceType = "_micbridge-v2._tcp"
let bridgeALPN = "micbridge/2"
let handshakeTimeout: TimeInterval = 8
let maxFramePayload = 64 * 1024

func log(_ message: String) { print("[\(Date().formatted(.iso8601))] \(message)") }

enum BridgeError: Error { case tls, random, invalidFrame, authentication, pairingUnavailable, storage }

func makeTLSIdentity() throws -> sec_identity_t {
    var keyBytes = [UInt8](repeating: 0, count: 97)
    var certBytes = [UInt8](repeating: 0, count: 2048)
    let n = mb_make_identity(&keyBytes, &certBytes, certBytes.count)
    defer { keyBytes.withUnsafeMutableBytes { _ = $0.initializeMemory(as: UInt8.self, repeating: 0) } }
    let attributes = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                      kSecAttrKeySizeInBits: 256] as CFDictionary
    guard n > 0, let cert = SecCertificateCreateWithData(nil, Data(certBytes.prefix(n)) as CFData),
          let key = SecKeyCreateWithData(Data(keyBytes) as CFData, attributes, nil),
          let identity = SecIdentityCreate(nil, cert, key), let result = sec_identity_create(identity) else {
        throw BridgeError.tls
    }
    return result
}

func secureParameters(identity: sec_identity_t? = nil, queue: DispatchQueue) -> NWParameters {
    let tls = NWProtocolTLS.Options()
    let opts = tls.securityProtocolOptions
    sec_protocol_options_set_min_tls_protocol_version(opts, .TLSv13)
    sec_protocol_options_set_max_tls_protocol_version(opts, .TLSv13)
    sec_protocol_options_add_tls_application_protocol(opts, bridgeALPN)
    sec_protocol_options_set_tls_tickets_enabled(opts, false)
    sec_protocol_options_set_tls_resumption_enabled(opts, false)
    sec_protocol_options_set_tls_false_start_enabled(opts, false)
    if let identity {
        sec_protocol_options_set_local_identity(opts, identity)
    } else {
        // The ephemeral certificate is not a trust anchor. The handshake below
        // authenticates this exact TLS channel before any audio/control frames.
        sec_protocol_options_set_verify_block(opts, { _, _, complete in complete(true) }, queue)
    }
    let tcp = NWProtocolTCP.Options()
    tcp.noDelay = true
    tcp.enableKeepalive = true
    tcp.keepaliveIdle = 10
    tcp.keepaliveInterval = 5
    tcp.keepaliveCount = 2
    tcp.connectionTimeout = 5
    return NWParameters(tls: tls, tcp: tcp)
}

func channelBinding(_ connection: NWConnection) throws -> Data {
    guard let tls = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
        throw BridgeError.tls
    }
    var binding = [UInt8](repeating: 0, count: 32)
    guard mb_channel_binding(tls.securityProtocolMetadata, &binding) == 1 else { throw BridgeError.tls }
    return Data(binding)
}

struct BridgeFrame: Equatable {
    enum Kind: UInt8 {
        case pairHello = 1, pairReply, pairProof, pairAccepted, authHello, authAccepted
        case start = 83, pause = 80, header = 72, audio = 65, paused = 7

        func accepts(_ length: Int) -> Bool {
            switch self {
            case .pairHello, .pairReply, .pairProof, .pairAccepted, .authHello, .authAccepted: return length == 32
            case .start, .pause, .paused: return length == 0
            case .header: return length == 4
            case .audio: return length > 0 && length <= maxFramePayload && length.isMultiple(of: 2)
            }
        }
    }
    let kind: Kind
    let payload: Data
    init(_ kind: Kind, _ payload: Data = Data()) { self.kind = kind; self.payload = payload }

    func encode() -> Data {
        var bytes = Data([kind.rawValue])
        withUnsafeBytes(of: UInt32(payload.count).bigEndian) { bytes.append(contentsOf: $0) }
        bytes.append(payload)
        return bytes
    }
}

struct BridgeDecoder {
    private var pending = Data()

    mutating func append(_ bytes: Data) throws -> [BridgeFrame] {
        pending.append(bytes)
        var frames: [BridgeFrame] = []
        var offset = 0
        while pending.count - offset >= 5 {
            let start = pending.startIndex + offset
            let length = pending.withUnsafeBytes {
                Int(UInt32(bigEndian: $0.loadUnaligned(fromByteOffset: offset + 1, as: UInt32.self)))
            }
            guard length <= maxFramePayload, let kind = BridgeFrame.Kind(rawValue: pending[start]),
                  kind.accepts(length) else { throw BridgeError.invalidFrame }
            guard pending.count - offset - 5 >= length else { break }
            frames.append(BridgeFrame(kind, pending.subdata(in: (start + 5)..<(start + 5 + length))))
            offset += 5 + length
        }
        pending.removeFirst(offset)
        return frames
    }
}

func validPIN(_ pin: String) -> Bool { pin.utf8.count == 4 && pin.utf8.allSatisfy { (48...57).contains($0) } }

func randomPIN() throws -> String {
    var word: UInt16 = 0
    repeat {
        guard SecRandomCopyBytes(kSecRandomDefault, MemoryLayout<UInt16>.size, &word) == errSecSuccess else {
            throw BridgeError.random
        }
    } while word >= 60_000 // Rejection sampling keeps all 10,000 codes equally likely.
    return String(format: "%04d", Int(word % 10_000))
}

struct PairingWindow {
    let pin: String
    let deadline: TimeInterval
    private(set) var remaining = 3

    init(pin: String, now: TimeInterval) { self.pin = pin; deadline = now + 120 }
    mutating func takeAttempt(now: TimeInterval) throws -> String {
        guard now < deadline, remaining > 0 else { throw BridgeError.pairingUnavailable }
        remaining -= 1
        return pin
    }
}

private final class SPAKE {
    private let context: UnsafeMutableRawPointer
    let message: Data

    init(pin: String, receiver: Bool) throws {
        guard validPIN(pin), let context = mb_spake_new(receiver ? 1 : 0) else { throw BridgeError.authentication }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard mb_spake_start(context, Array(pin.utf8), &bytes) == 1 else {
            mb_spake_free(context)
            throw BridgeError.authentication
        }
        self.context = context
        message = Data(bytes)
    }

    deinit { mb_spake_free(context) }

    func finish(peer: Data, exporter: Data, receiver: Bool) throws -> PairSecrets {
        guard peer.count == 32 else { throw BridgeError.invalidFrame }
        var secret = [UInt8](repeating: 0, count: 64)
        defer { secret.withUnsafeMutableBytes { _ = $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        guard mb_spake_finish(context, Array(peer), &secret) == 1 else { throw BridgeError.authentication }
        return PairSecrets(secret: SymmetricKey(data: secret), exporter: exporter,
                           receiverMessage: receiver ? message : peer, senderMessage: receiver ? peer : message)
    }
}

private struct PairSecrets {
    let transcript: Data
    let receiverConfirmation: SymmetricKey
    let senderConfirmation: SymmetricKey
    let pairingKey: Data

    init(secret: SymmetricKey, exporter: Data, receiverMessage: Data, senderMessage: Data) {
        transcript = Data("micbridge/2 pair transcript".utf8) + exporter + receiverMessage + senderMessage
        let salt = Data(SHA256.hash(data: transcript))
        func derive(_ label: String) -> SymmetricKey {
            HKDF<SHA256>.deriveKey(inputKeyMaterial: secret, salt: salt,
                                   info: Data("micbridge/2 \(label)".utf8), outputByteCount: 32)
        }
        receiverConfirmation = derive("receiver confirmation")
        senderConfirmation = derive("sender confirmation")
        pairingKey = derive("pairing key").withUnsafeBytes { Data($0) }
    }

    func proof(receiver: Bool) -> Data {
        let key = receiver ? receiverConfirmation : senderConfirmation
        return mac(key: key, data: transcript)
    }

    func verifies(_ proof: Data, receiver: Bool) -> Bool {
        let key = receiver ? receiverConfirmation : senderConfirmation
        return HMAC<SHA256>.isValidAuthenticationCode(proof, authenticating: transcript, using: key)
    }
}

private func mac(key: SymmetricKey, data: Data) -> Data {
    Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
}

private func authTranscript(_ exporter: Data, receiver: Bool) -> Data {
    Data("micbridge/2 auth \(receiver ? "receiver" : "sender")".utf8) + exporter
}

// State and frame direction are checked before calling any application code.
final class Handshake {
    enum Result { case send(BridgeFrame), paired(BridgeFrame?), authenticated(BridgeFrame?), application(BridgeFrame) }
    private enum State { case sender, wantPairReply(SPAKE), wantPairProof(PairSecrets), wantPairAccepted(PairSecrets)
                         case wantAuthAccepted(Data), authenticated, finished }
    private let exporter: Data
    private let receiver: Bool
    private var state: State

    private init(exporter: Data, receiver: Bool, state: State) {
        self.exporter = exporter; self.receiver = receiver; self.state = state
    }

    static func sender(exporter: Data) -> Handshake { Handshake(exporter: exporter, receiver: false, state: .sender) }
    static func pairingReceiver(exporter: Data, pin: String) throws -> (Handshake, BridgeFrame) {
        let spake = try SPAKE(pin: pin, receiver: true)
        return (Handshake(exporter: exporter, receiver: true, state: .wantPairReply(spake)), BridgeFrame(.pairHello, spake.message))
    }

    static func knownReceiver(exporter: Data, key: Data) -> (Handshake, BridgeFrame) {
        let transcript = authTranscript(exporter, receiver: true)
        let proof = mac(key: SymmetricKey(data: key), data: transcript)
        return (Handshake(exporter: exporter, receiver: true, state: .wantAuthAccepted(key)), BridgeFrame(.authHello, proof))
    }

    func receive(_ frame: BridgeFrame, key: Data? = nil, takePIN: () throws -> String = { throw BridgeError.pairingUnavailable },
                 save: (Data) throws -> Void = { _ in throw BridgeError.storage }) throws -> Result {
        guard frame.kind.accepts(frame.payload.count) else { throw BridgeError.invalidFrame }
        switch (state, frame.kind) {
        case (.sender, .pairHello):
            guard key == nil else { throw BridgeError.pairingUnavailable }
            let spake = try SPAKE(pin: takePIN(), receiver: false)
            let secrets = try spake.finish(peer: frame.payload, exporter: exporter, receiver: false)
            state = .wantPairProof(secrets)
            return .send(BridgeFrame(.pairReply, spake.message))
        case (.wantPairReply(let spake), .pairReply):
            let secrets = try spake.finish(peer: frame.payload, exporter: exporter, receiver: true)
            state = .wantPairAccepted(secrets)
            return .send(BridgeFrame(.pairProof, secrets.proof(receiver: true)))
        case (.wantPairProof(let secrets), .pairProof):
            state = .finished
            guard secrets.verifies(frame.payload, receiver: true) else { throw BridgeError.authentication }
            try save(secrets.pairingKey)
            return .paired(BridgeFrame(.pairAccepted, secrets.proof(receiver: false)))
        case (.wantPairAccepted(let secrets), .pairAccepted):
            state = .finished
            guard secrets.verifies(frame.payload, receiver: false) else { throw BridgeError.authentication }
            try save(secrets.pairingKey)
            return .paired(nil)
        case (.sender, .authHello):
            guard let key else { throw BridgeError.authentication }
            let secret = SymmetricKey(data: key)
            guard HMAC<SHA256>.isValidAuthenticationCode(frame.payload, authenticating: authTranscript(exporter, receiver: true),
                                                         using: secret) else { throw BridgeError.authentication }
            state = .authenticated
            return .authenticated(BridgeFrame(.authAccepted, mac(key: secret, data: authTranscript(exporter, receiver: false))))
        case (.wantAuthAccepted(let key), .authAccepted):
            guard HMAC<SHA256>.isValidAuthenticationCode(frame.payload, authenticating: authTranscript(exporter, receiver: false),
                                                         using: SymmetricKey(data: key)) else { throw BridgeError.authentication }
            state = .authenticated
            return .authenticated(nil)
        case (.authenticated, .header), (.authenticated, .audio), (.authenticated, .paused):
            guard receiver else { throw BridgeError.invalidFrame }
            return .application(frame)
        case (.authenticated, .start), (.authenticated, .pause):
            guard !receiver else { throw BridgeError.invalidFrame }
            return .application(frame)
        default: throw BridgeError.invalidFrame
        }
    }
}

// Owned and driven exclusively by the caller's serial queue.
final class BridgeConnection {
    let connection: NWConnection
    var handshake: Handshake?
    private var decoder = BridgeDecoder()
    private(set) var closed = false
    private var onFrame: ((BridgeFrame) throws -> Void)?
    private var onClose: ((Error?) -> Void)?

    init(_ connection: NWConnection) { self.connection = connection }

    func start(on queue: DispatchQueue, ready: @escaping (Data) throws -> Void,
               frame: @escaping (BridgeFrame) throws -> Void, closed: @escaping (Error?) -> Void) {
        onFrame = frame
        onClose = closed
        connection.stateUpdateHandler = { [weak self] state in
            guard let self, !self.closed else { return }
            switch state {
            case .ready:
                do { try ready(channelBinding(self.connection)); self.read() }
                catch { self.close(error) }
            case .failed(let error), .waiting(let error): self.close(error)
            case .cancelled: self.close()
            default: break
            }
        }
        connection.start(queue: queue)
    }

    func send(_ frame: BridgeFrame, finished: (() -> Void)? = nil) {
        guard !closed else { return }
        connection.send(content: frame.encode(), completion: .contentProcessed { [weak self] error in
            guard let self, !self.closed else { return }
            if let error { self.close(error) } else { finished?() }
        })
    }

    func close(_ error: Error? = nil) {
        guard !closed else { return }
        closed = true
        connection.stateUpdateHandler = nil
        connection.cancel()
        handshake = nil
        onFrame = nil
        let callback = onClose
        onClose = nil
        callback?(error)
    }

    private func read() {
        guard !closed else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 16384) { [weak self] data, _, done, error in
            guard let self, !self.closed else { return }
            do {
                if let data {
                    for frame in try self.decoder.append(data) {
                        guard !self.closed else { break }
                        try self.onFrame?(frame)
                    }
                }
                if done || error != nil { self.close(error) } else { self.read() }
            } catch { self.close(error) }
        }
    }
}
