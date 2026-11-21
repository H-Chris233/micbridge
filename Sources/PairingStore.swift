import Foundation

struct PairingStore {
    private let directory: URL
    private let file: URL

    init(role: String, directory: URL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/MicBridge", isDirectory: true)) {
        self.directory = directory
        file = directory.appendingPathComponent("\(role).key")
    }

    private func checkDirectory(create: Bool) throws -> Bool {
        if create && mkdir(directory.path, 0o700) != 0 && errno != EEXIST { throw BridgeError.storage }
        var info = stat()
        if lstat(directory.path, &info) != 0 {
            if !create && errno == ENOENT { return false }
            throw BridgeError.storage
        }
        guard info.st_mode & S_IFMT == S_IFDIR, info.st_mode & 0o777 == 0o700,
              info.st_uid == getuid() else { throw BridgeError.storage }
        return true
    }

    func load() throws -> Data? {
        guard try checkDirectory(create: false) else { return nil }
        let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw BridgeError.storage
        }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o777 == 0o600, info.st_uid == getuid(), info.st_size == 32,
              let key = try handle.read(upToCount: 33), key.count == 32 else { throw BridgeError.storage }
        return key
    }

    func save(_ key: Data) throws {
        guard key.count == 32, try checkDirectory(create: true) else { throw BridgeError.storage }
        var temp = directory.appendingPathComponent(".key.XXXXXX").path.utf8CString
        let fd = temp.withUnsafeMutableBufferPointer { mkstemp($0.baseAddress!) }
        guard fd >= 0 else { throw BridgeError.storage }
        let path = temp.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        defer { unlink(path) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        guard fchmod(fd, 0o600) == 0 else { throw BridgeError.storage }
        do {
            try handle.write(contentsOf: key)
            try handle.synchronize()
            try handle.close()
        } catch { throw BridgeError.storage }
        guard rename(path, file.path) == 0 else { throw BridgeError.storage }
    }

    func remove() throws {
        guard try checkDirectory(create: false) else { return }
        guard unlink(file.path) == 0 || errno == ENOENT else { throw BridgeError.storage }
    }
}
