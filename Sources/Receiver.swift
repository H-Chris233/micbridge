// MicBridge Receiver — runs on the Mac mini.
// Watches whether any app is recording from the BlackHole virtual device.
// It keeps an authenticated TLS connection to the sender open. When an app
// records, it requests the microphone and plays incoming audio into BlackHole.
// After recording stops, it asks the sender to switch the microphone off again.

import AppKit
import AudioToolbox
import CoreAudio
import Foundation
import Network

@main
struct ReceiverMain {
    static func main() {
        setvbuf(stdout, nil, _IOLBF, 0)
        var options = ReceiverOptions()
        var args = CommandLine.arguments.dropFirst().makeIterator()
        func usage() -> Never {
            print("usage: micbridge-receiver [--host IP] [--port N] [--device NAME] [--always-on] [--no-set-default]")
            exit(2)
        }
        while let arg = args.next() {
            switch arg {
            case "--host": guard let value = args.next(), !value.isEmpty else { usage() }; options.host = value
            case "--port": guard let text = args.next(), let value = UInt16(text), value != 0 else { usage() }; options.port = value
            case "--device": guard let value = args.next(), !value.isEmpty else { usage() }; options.device = value
            case "--always-on": options.alwaysOn = true
            case "--no-set-default": options.setDefault = false
            default: usage()
            }
        }
        guard let device = findDevice(matching: options.device) else {
            log("no audio device matching \(options.device) — install BlackHole first: brew install --cask blackhole-2ch")
            exit(1)
        }
        log("using virtual device: \(deviceName(device))")
        if options.setDefault { setDefaultInput(device) }
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let receiver = Receiver(device: device, options: options)
        let menu = MenuBar(sender: false, begin: { receiver.requestPairing() }, forget: { receiver.forget() })
        receiver.menu = menu
        receiver.start()
        withExtendedLifetime(menu) { app.run() }
    }
}

struct ReceiverOptions {
    var host: String?
    var port: UInt16 = 50555
    var device = "BlackHole"
    var alwaysOn = false
    var setDefault = true
}

// MARK: - Core Audio helpers

func getProperty<T>(_ obj: AudioObjectID, _ selector: AudioObjectPropertySelector,
                    scope: AudioObjectPropertyScope = kAudioObjectPropertyScopeGlobal) -> [T] {
    var addr = AudioObjectPropertyAddress(mSelector: selector, mScope: scope, mElement: kAudioObjectPropertyElementMain)
    var size: UInt32 = 0
    guard AudioObjectGetPropertyDataSize(obj, &addr, 0, nil, &size) == noErr, size > 0 else { return [] }
    let count = Int(size) / MemoryLayout<T>.stride
    let ptr = UnsafeMutableRawPointer.allocate(byteCount: Int(size), alignment: MemoryLayout<T>.alignment)
    defer { ptr.deallocate() }
    guard AudioObjectGetPropertyData(obj, &addr, 0, nil, &size, ptr) == noErr else { return [] }
    let typed = ptr.bindMemory(to: T.self, capacity: count)
    return Array(UnsafeBufferPointer(start: typed, count: Int(size) / MemoryLayout<T>.stride))
}

func deviceName(_ id: AudioDeviceID) -> String {
    var addr = AudioObjectPropertyAddress(mSelector: kAudioObjectPropertyName,
                                          mScope: kAudioObjectPropertyScopeGlobal,
                                          mElement: kAudioObjectPropertyElementMain)
    var name: Unmanaged<CFString>?
    var size = UInt32(MemoryLayout<Unmanaged<CFString>?>.size)
    guard AudioObjectGetPropertyData(id, &addr, 0, nil, &size, &name) == noErr, let n = name else { return "" }
    return n.takeRetainedValue() as String
}

func findDevice(matching: String) -> AudioDeviceID? {
    let ids: [AudioDeviceID] = getProperty(AudioObjectID(kAudioObjectSystemObject), kAudioHardwarePropertyDevices)
    return ids.first { deviceName($0).localizedCaseInsensitiveContains(matching) }
}

func setDefaultInput(_ id: AudioDeviceID) {
    var dev = id
    var addr = AudioObjectPropertyAddress(mSelector: kAudioHardwarePropertyDefaultInputDevice,
                                          mScope: kAudioObjectPropertyScopeGlobal,
                                          mElement: kAudioObjectPropertyElementMain)
    AudioObjectSetPropertyData(AudioObjectID(kAudioObjectSystemObject), &addr, 0, nil,
                               UInt32(MemoryLayout<AudioDeviceID>.size), &dev)
}

/// True when some process other than us is currently recording from `device`.
func someoneIsRecording(from device: AudioDeviceID) -> Bool {
    let me = getpid()
    let procs: [AudioObjectID] = getProperty(AudioObjectID(kAudioObjectSystemObject), kAudioHardwarePropertyProcessObjectList)
    for p in procs {
        let pid: [pid_t] = getProperty(p, kAudioProcessPropertyPID)
        guard let pid = pid.first, pid != me else { continue }
        let running: [UInt32] = getProperty(p, kAudioProcessPropertyIsRunningInput)
        guard running.first ?? 0 != 0 else { continue }
        let devices: [AudioObjectID] = getProperty(p, kAudioProcessPropertyDevices, scope: kAudioObjectPropertyScopeInput)
        if devices.isEmpty || devices.contains(device) { return true }
    }
    return false
}

// MARK: - Jitter buffer

final class RingBuffer {
    private var buf: [Float]
    private var readIdx = 0, writeIdx = 0
    private(set) var count = 0
    private var lock = os_unfair_lock()
    private var primed = false
    let target: Int, maxFill: Int

    init(sampleRate: Double) {
        buf = [Float](repeating: 0, count: Int(sampleRate * 2))
        target = Int(sampleRate * 0.04)   // ~40 ms cushion before playback starts
        maxFill = Int(sampleRate * 0.2)   // drop old audio if latency builds past 200 ms
    }

    func write(_ samples: [Float]) {
        os_unfair_lock_lock(&lock); defer { os_unfair_lock_unlock(&lock) }
        for s in samples {
            buf[writeIdx] = s
            writeIdx = (writeIdx + 1) % buf.count
            if count == buf.count { readIdx = (readIdx + 1) % buf.count } else { count += 1 }
        }
        if count > maxFill {
            let skip = count - target
            readIdx = (readIdx + skip) % buf.count
            count -= skip
        }
    }

    func reset() {
        os_unfair_lock_lock(&lock); defer { os_unfair_lock_unlock(&lock) }
        readIdx = 0; writeIdx = 0; count = 0; primed = false
    }

    func read(into out: UnsafeMutablePointer<Float>, frames: Int) {
        os_unfair_lock_lock(&lock); defer { os_unfair_lock_unlock(&lock) }
        if !primed && count >= target { primed = true }
        var i = 0
        if primed {
            while i < frames && count > 0 {
                out[i] = buf[readIdx]
                readIdx = (readIdx + 1) % buf.count
                count -= 1
                i += 1
            }
            if count == 0 { primed = false }  // underrun: re-buffer before resuming
        }
        while i < frames { out[i] = 0; i += 1 }
    }
}

// MARK: - Output to the virtual device

/// Plays the ring buffer into one specific device through its own HAL output unit.
/// Unlike AVAudioEngine's output node, this stays on that device when the user
/// changes the system's default output (e.g. back to the speakers).
final class DeviceOutput {
    private var unit: AudioUnit
    private let ring: RingBuffer

    struct Failure: Error, CustomStringConvertible {
        let step: String, status: OSStatus
        var description: String { "\(step) failed (\(status))" }
    }

    init(device: AudioDeviceID, sampleRate: Double, ring: RingBuffer) throws {
        self.ring = ring
        var desc = AudioComponentDescription(componentType: kAudioUnitType_Output,
                                             componentSubType: kAudioUnitSubType_HALOutput,
                                             componentManufacturer: kAudioUnitManufacturer_Apple,
                                             componentFlags: 0, componentFlagsMask: 0)
        guard let comp = AudioComponentFindNext(nil, &desc) else { throw Failure(step: "find HAL output", status: -1) }
        var u: AudioUnit?
        try Self.check("create output unit", AudioComponentInstanceNew(comp, &u))
        unit = u!

        var dev = device
        try Self.check("select device", AudioUnitSetProperty(unit, kAudioOutputUnitProperty_CurrentDevice,
            kAudioUnitScope_Global, 0, &dev, UInt32(MemoryLayout<AudioDeviceID>.size)))

        // Stereo, so apps recording either channel of BlackHole hear the mic.
        var fmt = AudioStreamBasicDescription(
            mSampleRate: sampleRate, mFormatID: kAudioFormatLinearPCM,
            mFormatFlags: kAudioFormatFlagIsFloat | kAudioFormatFlagIsPacked | kAudioFormatFlagIsNonInterleaved,
            mBytesPerPacket: 4, mFramesPerPacket: 1, mBytesPerFrame: 4, mChannelsPerFrame: 2,
            mBitsPerChannel: 32, mReserved: 0)
        try Self.check("set format", AudioUnitSetProperty(unit, kAudioUnitProperty_StreamFormat,
            kAudioUnitScope_Input, 0, &fmt, UInt32(MemoryLayout<AudioStreamBasicDescription>.size)))

        var cb = AURenderCallbackStruct(inputProc: { refCon, _, _, _, frames, abl in
            let ring = Unmanaged<RingBuffer>.fromOpaque(refCon).takeUnretainedValue()
            let buffers = UnsafeMutableAudioBufferListPointer(abl!)
            guard let first = buffers.first?.mData?.assumingMemoryBound(to: Float.self) else { return noErr }
            ring.read(into: first, frames: Int(frames))
            for b in buffers.dropFirst() {
                b.mData?.copyMemory(from: first, byteCount: Int(frames) * 4)
            }
            return noErr
        }, inputProcRefCon: Unmanaged.passUnretained(ring).toOpaque())
        try Self.check("set render callback", AudioUnitSetProperty(unit, kAudioUnitProperty_SetRenderCallback,
            kAudioUnitScope_Input, 0, &cb, UInt32(MemoryLayout<AURenderCallbackStruct>.size)))

        try Self.check("initialize", AudioUnitInitialize(unit))
        try Self.check("start", AudioOutputUnitStart(unit))
    }

    func stop() {
        AudioOutputUnitStop(unit)
        AudioUnitUninitialize(unit)
        AudioComponentInstanceDispose(unit)
    }

    private static func check(_ step: String, _ status: OSStatus) throws {
        if status != noErr { throw Failure(step: step, status: status) }
    }
}

// MARK: - Receiver

final class Receiver {
    private let queue = DispatchQueue(label: "micbridge.receiver")
    private let device: AudioDeviceID
    private let options: ReceiverOptions
    private let store = PairingStore(role: "receiver")
    weak var menu: MenuBar?
    private var browser: NWBrowser?
    private var timer: DispatchSourceTimer?
    private var candidates: [NWEndpoint] = []
    private var nextCandidate = 0
    private var nextAttempt: TimeInterval = 0
    private var tried = 0
    private var failures = 0
    private var pairingKey: Data?
    private var storageError = false
    private var choosing = false
    private var pairing = false
    private var conn: BridgeConnection?
    private var authenticated = false
    private var micRequested = false
    private var hasHeader = false
    private var pauseSentAt: TimeInterval?
    private var output: DeviceOutput?
    private var outputRate: Double = 0
    private var ring: RingBuffer?
    private var idleSince: TimeInterval?
    private var requestedAt: TimeInterval?
    private var now: TimeInterval { ProcessInfo.processInfo.systemUptime }

    init(device: AudioDeviceID, options: ReceiverOptions) { self.device = device; self.options = options }

    func start() {
        queue.async { [self] in
            do { self.pairingKey = try self.store.load() }
            catch { self.storageError = true; log("cannot read receiver pairing record") }
            if let host = self.options.host, let port = NWEndpoint.Port(rawValue: self.options.port) {
                self.candidates = [.hostPort(host: NWEndpoint.Host(host), port: port)]
            } else {
                let browser = NWBrowser(for: .bonjour(type: serviceType, domain: nil), using: .tcp)
                browser.browseResultsChangedHandler = { [weak self] results, _ in
                    guard let self else { return }
                    let endpoints = Set(results.map(\.endpoint)).sorted { $0.debugDescription < $1.debugDescription }
                    guard endpoints != self.candidates else { return }
                    self.candidates = endpoints
                    self.resetRetry()
                    if !self.pairing, !self.authenticated, let conn = self.conn,
                       !endpoints.contains(conn.connection.endpoint) { conn.close() }
                }
                browser.start(queue: self.queue)
                self.browser = browser
            }
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now(), repeating: .milliseconds(250))
            timer.setEventHandler { [weak self] in self?.tick() }
            self.timer = timer
            self.updateMenu()
            timer.resume()
        }
    }

    func requestPairing() {
        queue.async { [self] in
            guard !self.choosing, !self.pairing, self.pairingKey == nil, !self.storageError else { return }
            self.choosing = true
            self.updateMenu()
            let endpoints = self.candidates
            let names = endpoints.map { endpoint in
                if case let .service(name, _, domain, interface) = endpoint {
                    return interface.map { "\(name) (\($0.name))" } ?? "\(name) (\(domain))"
                }
                return endpoint.debugDescription
            }
            DispatchQueue.main.async {
                let selection = self.menu?.requestPIN(names: names)
                self.queue.async { [self] in
                    self.choosing = false
                    self.updateMenu()
                    guard let (index, pin) = selection, endpoints.indices.contains(index), self.pairingKey == nil,
                          !self.storageError else { return }
                    guard validPIN(pin) else { self.showMessage("请输入恰好 4 位数字", "例如 0042。"); return }
                    self.pairing = true
                    self.updateMenu()
                    self.connect(endpoints[index], pin: pin)
                }
            }
        }
    }

    func forget() {
        queue.async { [self] in
            self.pairingKey = nil
            self.pairing = false
            self.conn?.close()
            do { try self.store.remove(); self.storageError = false }
            catch {
                self.storageError = true
                self.showMessage("未能删除配对记录", "本次运行已禁止连接。修复文件权限后重试；重启前请确认已删除记录。")
            }
            self.updateMenu()
        }
    }

    private func updateMenu() {
        let paired = pairingKey != nil, busy = choosing || pairing, error = storageError, connected = authenticated
        DispatchQueue.main.async { [weak self] in
            self?.menu?.update(paired: paired, busy: busy, storageError: error, connected: connected)
        }
    }

    private func showMessage(_ title: String, _ detail: String) {
        DispatchQueue.main.async { [weak self] in self?.menu?.alert(title, detail) }
    }

    private func resetRetry() { nextCandidate = 0; nextAttempt = 0; tried = 0; failures = 0 }

    private func tick() {
        if conn == nil, pairingKey != nil, !storageError, !candidates.isEmpty, now >= nextAttempt {
            let endpoint = candidates[nextCandidate % candidates.count]
            nextCandidate = (nextCandidate + 1) % candidates.count
            tried += 1
            connect(endpoint)
        }
        guard authenticated, let conn else { return }
        if let pauseSentAt {
            if now - pauseSentAt >= handshakeTimeout { conn.close() }
            return
        }
        if options.alwaysOn || someoneIsRecording(from: device) {
            idleSince = nil
            if !micRequested {
                log("requesting the paired microphone")
                micRequested = true
                hasHeader = false
                requestedAt = now
                conn.send(BridgeFrame(.start))
            }
        } else if micRequested {
            // Short grace period so brief pauses between recordings don't bounce the mic.
            if idleSince == nil { idleSince = now }
            if let idleSince, now - idleSince >= 3 {
                log("no app is recording any more — turning the MacBook mic off")
                micRequested = false
                hasHeader = false
                requestedAt = nil
                ring?.reset()
                pauseSentAt = now
                conn.send(BridgeFrame(.pause))
            }
        }
    }

    // The authenticated connection stays open across recordings.
    private func connect(_ endpoint: NWEndpoint, pin: String? = nil) {
        let client = BridgeConnection(NWConnection(to: endpoint, using: secureParameters(queue: queue)))
        conn = client
        var submittedPIN = pin
        client.start(on: queue, ready: { [weak self, weak client] exporter in
            guard let self, let client, self.conn === client else { return }
            let (handshake, hello): (Handshake, BridgeFrame)
            if let pin = submittedPIN {
                submittedPIN = nil
                (handshake, hello) = try Handshake.pairingReceiver(exporter: exporter, pin: pin)
            } else if let key = self.pairingKey {
                (handshake, hello) = Handshake.knownReceiver(exporter: exporter, key: key)
            } else { throw BridgeError.authentication }
            client.handshake = handshake
            client.send(hello)
        }, frame: { [weak self, weak client] frame in
            guard let self, let client, self.conn === client, let handshake = client.handshake else { return }
            let result = try handshake.receive(frame, save: { key in
                try self.store.save(key)
                self.pairingKey = key
            })
            switch result {
            case .send(let reply): client.send(reply)
            case .paired:
                self.pairing = false
                client.close()
                self.resetRetry()
                log("sender paired")
            case .authenticated:
                self.authenticated = true
                self.resetRetry()
                self.updateMenu()
                log("connected to the paired sender")
            case .application(let frame): try self.play(frame)
            }
        }, closed: { [weak self, weak client] error in
            guard let self, let client, self.conn === client else { return }
            self.didClose(error)
        })
        queue.asyncAfter(deadline: .now() + handshakeTimeout) { [weak self, weak client] in
            guard let self, let client, self.conn === client, !self.authenticated else { return }
            client.close(BridgeError.authentication)
        }
    }

    private func didClose(_ error: Error?) {
        let wasPairing = pairing
        let wasAuthenticated = authenticated
        conn = nil
        pairing = false
        authenticated = false
        micRequested = false
        hasHeader = false
        idleSince = nil
        pauseSentAt = nil
        requestedAt = nil
        output?.stop()
        output = nil
        outputRate = 0
        ring = nil
        updateMenu()
        if wasPairing {
            let detail = (error as? BridgeError) == .storage
                ? "无法保存配对记录。请检查文件权限，并在发送端取消配对后重试。"
                : "请确认发送端仍显示有效配对码，再重新输入。若发送端已显示已配对，请先在发送端取消配对。"
            showMessage("配对失败", detail)
        } else if wasAuthenticated {
            log("disconnected from the paired sender")
        }
        if pairingKey != nil, tried >= candidates.count {
            tried = 0
            let delay = min(30, 2 * pow(2, Double(min(failures, 4))))
            nextAttempt = now + delay
            failures += 1
            if failures == 1 { log("cannot authenticate a sender — retrying in the background") }
        }
    }

    private func play(_ frame: BridgeFrame) throws {
        guard authenticated else { throw BridgeError.authentication }
        if frame.kind == .paused {
            guard pauseSentAt != nil else { throw BridgeError.invalidFrame }
            pauseSentAt = nil
            return
        }
        // Frames already in flight when pause was sent must not refill the buffer.
        guard micRequested else { return }
        if frame.kind == .header {
            let rate = Double(frame.payload.withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) })
            guard !hasHeader, (8_000...384_000).contains(rate) else { throw BridgeError.invalidFrame }
            hasHeader = true
            ensurePlayback(sampleRate: rate)
            ring?.reset()
            if let t = requestedAt {
                log(String(format: "MacBook mic is on (%.2f s after the request)", now - t))
                requestedAt = nil
            }
        } else {
            guard hasHeader else { throw BridgeError.invalidFrame }
            let samples = frame.payload.withUnsafeBytes { raw in
                (0..<(raw.count / 2)).map { i in
                    Float(Int16(littleEndian: raw.loadUnaligned(fromByteOffset: i * 2, as: Int16.self))) / 32768
                }
            }
            ring?.write(samples)
        }
    }

    private func ensurePlayback(sampleRate: Double) {
        if output != nil && outputRate == sampleRate { return }
        output?.stop()
        output = nil
        let ring = RingBuffer(sampleRate: sampleRate)
        self.ring = ring
        do {
            output = try DeviceOutput(device: device, sampleRate: sampleRate, ring: ring)
            outputRate = sampleRate
            log("audio output ready → \(deviceName(device)) (\(Int(sampleRate)) Hz)")
        } catch {
            log("could not start audio output: \(error)")
            outputRate = 0
        }
    }
}
