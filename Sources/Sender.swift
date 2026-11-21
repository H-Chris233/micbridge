// MicBridge Sender — runs on the MacBook Air.
// Advertises itself on the LAN via Bonjour. The paired receiver stays connected
// and sends a command when it needs audio: "S" turns the microphone on and
// "P" turns it off. Audio is sent only on the authenticated TLS connection.
//
// Sender → receiver: "H" carries the UInt32 LE sample rate on mic start;
// "A" carries Int16 LE mono samples. See BridgeFrame for the shared envelope.

import AppKit
import AVFoundation
import Foundation
import Network

@main
struct SenderMain {
    static func main() {
        setvbuf(stdout, nil, _IOLBF, 0)
        var args = CommandLine.arguments.dropFirst().makeIterator()
        var port: UInt16 = 50555
        while let arg = args.next() {
            guard arg == "--port", let text = args.next(), let value = UInt16(text), value != 0 else {
                print("usage: micbridge-sender [--port N]")
                exit(2)
            }
            port = value
        }
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let sender = Sender(port: port)
        let menu = MenuBar(sender: true, begin: { sender.beginPairing() }, forget: { sender.forgetOrCancel() })
        sender.menu = menu
        AVCaptureDevice.requestAccess(for: .audio) { granted in
            if !granted {
                log("microphone permission denied — allow it in System Settings › Privacy & Security › Microphone")
            }
        }
        do { try sender.start() } catch { log("cannot start secure listener: \(error)"); exit(1) }
        withExtendedLifetime(menu) { app.run() }
    }
}

final class Sender {
    private let queue = DispatchQueue(label: "micbridge.sender")
    private let port: UInt16
    private let store = PairingStore(role: "sender")
    weak var menu: MenuBar?
    private var pairingKey: Data?
    private var storageError = false
    private var window: PairingWindow?
    private var windowID: UUID?
    private var attempts: [ObjectIdentifier: UUID] = [:]
    private var listener: NWListener?
    private var clients: [ObjectIdentifier: BridgeConnection] = [:]
    private var authenticated: BridgeConnection?
    private var active: BridgeConnection?
    private var audioQueued = 0
    private var engine: AVAudioEngine?
    private var captureID: UUID?
    private var activity: NSObjectProtocol?

    init(port: UInt16) { self.port = port }

    func start() throws {
        do { pairingKey = try store.load() } catch { storageError = true; log("cannot read sender pairing record") }
        let listener = try NWListener(using: secureParameters(identity: makeTLSIdentity(), queue: queue),
                                      on: NWEndpoint.Port(rawValue: port)!)
        listener.service = NWListener.Service(name: Host.current().localizedName ?? "MacBook", type: serviceType)
        listener.stateUpdateHandler = { [port] state in
            switch state {
            case .ready: log("listening securely on port \(port), advertised as \(serviceType)")
            case .failed(let e): log("listener failed: \(e)"); exit(1)
            default: break
            }
        }
        listener.newConnectionHandler = { [weak self] conn in
            guard let self else { conn.cancel(); return }
            self.accept(conn)
        }
        self.listener = listener
        updateMenu()
        listener.start(queue: queue)
    }

    func beginPairing() {
        queue.async { [self] in
            guard self.pairingKey == nil, !self.storageError, self.window == nil else { return }
            guard let pin = try? randomPIN() else {
                DispatchQueue.main.async { self.menu?.alert("无法生成配对码", "请重试。") }
                return
            }
            let id = UUID()
            self.windowID = id
            self.window = PairingWindow(pin: pin, now: ProcessInfo.processInfo.systemUptime)
            self.updateMenu()
            DispatchQueue.main.async { self.menu?.showCode(pin) }
            self.queue.asyncAfter(deadline: .now() + 120) { [weak self] in
                guard let self, self.windowID == id else { return }
                self.endWindow()
            }
        }
    }

    func forgetOrCancel() {
        queue.async { [self] in
            if self.window != nil { self.endWindow(); return }
            self.pairingKey = nil
            for client in Array(self.clients.values) { client.close() }
            self.stopMic()
            do { try self.store.remove(); self.storageError = false }
            catch {
                self.storageError = true
                DispatchQueue.main.async { self.menu?.alert("未能删除配对记录", "本次运行已禁止连接。修复文件权限后重试；重启前请确认已删除记录。") }
            }
            self.updateMenu()
        }
    }

    private func updateMenu() {
        let paired = pairingKey != nil, busy = window != nil, error = storageError, connected = authenticated != nil
        DispatchQueue.main.async { [weak self] in
            self?.menu?.update(paired: paired, busy: busy, storageError: error, connected: connected)
        }
    }

    private func endWindow(keeping accepted: BridgeConnection? = nil) {
        let inFlight = Array(attempts.keys)
        windowID = nil
        window = nil
        attempts.removeAll()
        for id in inFlight where clients[id] !== accepted { clients[id]?.close() }
        DispatchQueue.main.async { [weak self] in self?.menu?.closeCode() }
        updateMenu()
    }

    private func accept(_ conn: NWConnection) {
        guard clients.count - (authenticated == nil ? 0 : 1) < 4 else { conn.cancel(); return }
        let client = BridgeConnection(conn)
        let id = ObjectIdentifier(client)
        clients[id] = client
        client.start(on: queue, ready: { [weak client] exporter in
            client?.handshake = .sender(exporter: exporter)
        }, frame: { [weak self, weak client] frame in
            guard let self, let client, self.clients[id] === client else { return }
            try self.receive(frame, from: client, id: id)
        }, closed: { [weak self, weak client] _ in
            guard let self, let client, self.clients[id] === client else { return }
            self.drop(client, id: id)
        })
        queue.asyncAfter(deadline: .now() + handshakeTimeout) { [weak self, weak client] in
            guard let self, let client, self.clients[id] === client, self.authenticated !== client else { return }
            client.close()
        }
    }

    private func receive(_ frame: BridgeFrame, from client: BridgeConnection, id: ObjectIdentifier) throws {
        guard let handshake = client.handshake, !storageError else { throw BridgeError.authentication }
        let result = try handshake.receive(frame, key: pairingKey, takePIN: {
            guard let generation = self.windowID, let pin = try self.window?.takeAttempt(now: ProcessInfo.processInfo.systemUptime)
            else { throw BridgeError.pairingUnavailable }
            self.attempts[id] = generation
            if self.window?.remaining == 0 { DispatchQueue.main.async { [weak self] in self?.menu?.closeCode() } }
            return pin
        }, save: { key in
            guard self.pairingKey == nil, let generation = self.windowID, self.attempts[id] == generation,
                  let deadline = self.window?.deadline, ProcessInfo.processInfo.systemUptime < deadline else {
                throw BridgeError.pairingUnavailable
            }
            try self.store.save(key)
            self.pairingKey = key
        })
        switch result {
        case .send(let reply): client.send(reply)
        case .paired(let reply):
            guard let reply else { throw BridgeError.invalidFrame }
            endWindow(keeping: client)
            log("receiver paired")
            // The receiver closes after reading the receipt. Keep it alive until then
            // (or the existing handshake deadline) so cancellation cannot discard the receipt.
            client.send(reply)
        case .authenticated(let reply):
            guard authenticated == nil, let reply else { throw BridgeError.authentication }
            authenticated = client
            client.send(reply)
            updateMenu()
            log("paired receiver connected")
        case .application(let command):
            guard authenticated === client else { throw BridgeError.authentication }
            if command.kind == .start {
                if active !== client {
                    startMic()
                    if let engine {
                        active = client
                        var rate = UInt32(engine.inputNode.outputFormat(forBus: 0).sampleRate).littleEndian
                        client.send(BridgeFrame(.header, withUnsafeBytes(of: &rate) { Data($0) }))
                    } else {
                        client.close()
                    }
                }
            } else {
                if active === client { active = nil; stopMic() }
                client.send(BridgeFrame(.paused))
            }
        }
    }

    private func drop(_ client: BridgeConnection, id: ObjectIdentifier) {
        clients.removeValue(forKey: id)
        attempts.removeValue(forKey: id)
        if active === client { active = nil; stopMic() }
        if authenticated === client { authenticated = nil; audioQueued = 0; updateMenu(); log("receiver disconnected") }
        if window?.remaining == 0 && attempts.isEmpty { endWindow() }
    }

    private func startMic() {
        let captureID = UUID()
        let engine = AVAudioEngine()
        let input = engine.inputNode
        let format = input.outputFormat(forBus: 0)
        guard format.sampleRate > 0 else { log("no microphone available"); return }

        let sink = AVAudioSinkNode { [weak self] _, frames, abl -> OSStatus in
            guard let self else { return noErr }
            let buffers = UnsafeMutableAudioBufferListPointer(UnsafeMutablePointer(mutating: abl))
            guard let ch0 = buffers.first?.mData?.assumingMemoryBound(to: Float.self) else { return noErr }
            let n = Int(frames)
            guard n > 0 && n <= maxFramePayload / 2 else { return noErr }
            var data = Data(count: n * 2)
            data.withUnsafeMutableBytes { raw in
                for i in 0..<n {
                    let s = max(-1, min(1, ch0[i]))
                    raw.storeBytes(of: Int16(s * 32767).littleEndian, toByteOffset: i * 2, as: Int16.self)
                }
            }
            self.queue.async { [self] in
                guard self.captureID == captureID, let client = self.active, self.audioQueued < 8 else { return }
                self.audioQueued += 1
                client.send(BridgeFrame(.audio, data)) { [weak self, weak client] in
                    guard let self, let client, self.authenticated === client else { return }
                    self.audioQueued -= 1
                }
            }
            return noErr
        }
        engine.attach(sink)
        engine.connect(input, to: sink, format: format)
        do {
            try engine.start()
            self.captureID = captureID
            self.engine = engine
            activity = ProcessInfo.processInfo.beginActivity(
                options: [.userInitiated, .idleSystemSleepDisabled, .latencyCritical],
                reason: "Streaming microphone to Mac mini")
            log("microphone ON (\(Int(format.sampleRate)) Hz)")
        } catch {
            log("failed to start microphone: \(error)")
        }
    }

    private func stopMic() {
        captureID = nil
        guard engine != nil else { return }
        engine?.stop()
        engine = nil
        if let a = activity { ProcessInfo.processInfo.endActivity(a); activity = nil }
        log("microphone OFF")
    }
}
