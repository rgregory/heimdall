import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - Paths

public enum Paths {
    public static var home: URL { FileManager.default.homeDirectoryForCurrentUser }

    /// ~/Library/Caches/Heimdall — downloaded feeds and lookup results. Safe to delete.
    public static var cache: URL {
        let base = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first ?? home.appendingPathComponent(".cache")
        return ensure(base.appendingPathComponent("Heimdall", isDirectory: true))
    }
    /// ~/Library/Application Support/Heimdall — reports and settings.
    public static var support: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first ?? home.appendingPathComponent(".local/share")
        return ensure(base.appendingPathComponent("Heimdall", isDirectory: true))
    }
    @discardableResult
    public static func ensure(_ u: URL) -> URL {
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }
    public static func expand(_ p: String) -> String {
        p.hasPrefix("~") ? home.path + p.dropFirst() : p
    }
}

// MARK: - Files

enum FS {
    static let fm = FileManager.default
    static func exists(_ p: String) -> Bool { fm.fileExists(atPath: p) }
    static func isDir(_ p: String) -> Bool { var d: ObjCBool = false; return fm.fileExists(atPath: p, isDirectory: &d) && d.boolValue }
    static func list(_ p: String) -> [String] { (try? fm.contentsOfDirectory(atPath: p))?.sorted() ?? [] }
    static func read(_ p: String) -> Data? { fm.contents(atPath: p) }
    static func text(_ p: String) -> String? { read(p).flatMap { String(data: $0, encoding: .utf8) } }
    static func mtime(_ p: String) -> Date? { (try? fm.attributesOfItem(atPath: p))?[.modificationDate] as? Date }
    static func resolve(_ p: String) -> String { URL(fileURLWithPath: p).resolvingSymlinksInPath().path }

    /// Expand a pattern with `*` wildcards in any path component ("/opt/homebrew/lib/python3.*/site-packages").
    static func glob(_ pattern: String) -> [String] {
        let parts = Paths.expand(pattern).split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        var paths = [""]
        for part in parts {
            var next: [String] = []
            for base in paths {
                let dir = base.isEmpty ? "/" : base
                if part.contains("*") {
                    let rx = "^" + NSRegularExpression.escapedPattern(for: part).replacingOccurrences(of: "\\*", with: ".*") + "$"
                    for e in list(dir) where e.range(of: rx, options: .regularExpression) != nil { next.append(base + "/" + e) }
                } else {
                    let p = base + "/" + part
                    if exists(p) { next.append(p) }
                }
            }
            paths = next
            if paths.isEmpty { break }
        }
        return paths
    }
}

// MARK: - Regex

extension String {
    /// Capture groups of the first match (index 0 = whole match).
    func firstMatch(_ pattern: String, options: NSRegularExpression.Options = []) -> [String]? {
        guard let rx = try? NSRegularExpression(pattern: pattern, options: options),
              let m = rx.firstMatch(in: self, range: NSRange(startIndex..., in: self)) else { return nil }
        return (0..<m.numberOfRanges).map { i in Range(m.range(at: i), in: self).map { String(self[$0]) } ?? "" }
    }
    func allMatches(_ pattern: String, options: NSRegularExpression.Options = []) -> [[String]] {
        guard let rx = try? NSRegularExpression(pattern: pattern, options: options) else { return [] }
        return rx.matches(in: self, range: NSRange(startIndex..., in: self)).map { m in
            (0..<m.numberOfRanges).map { i in Range(m.range(at: i), in: self).map { String(self[$0]) } ?? "" }
        }
    }
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}

// MARK: - Shell

public struct ShellResult: Sendable {
    public var status: Int32
    public var stdout: String
    public var stderr: String
    public var timedOut: Bool
    public var ok: Bool { status == 0 && !timedOut }
}

final class Buffer: @unchecked Sendable { var data = Data() }

public enum Shell {
    /// One literal POSIX-shell argument, including embedded apostrophes.
    static func quote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    /// The user's login-shell PATH plus the usual tool locations. GUI apps start with a bare
    /// PATH, so brew, pip and friends would otherwise be invisible.
    public static let path: String = {
        var parts: [String] = []
        let r = runSync("/bin/zsh", ["-lc", "printf %s \"$PATH\""], path: "/usr/bin:/bin:/usr/sbin:/sbin", timeout: 8)
        if r.ok { parts += r.stdout.split(separator: ":").map(String.init) }
        let h = Paths.home.path
        parts += ["/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "\(h)/.local/bin", "\(h)/.cargo/bin", "\(h)/go/bin",
                  "\(h)/.homebrew/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        return parts.filter { !$0.isEmpty }.uniqued().joined(separator: ":")
    }()

    public static func which(_ tool: String) -> String? {
        for dir in path.split(separator: ":") {
            let p = "\(dir)/\(tool)"
            if FileManager.default.isExecutableFile(atPath: p) { return p }
        }
        return nil
    }

    public static func run(_ exe: String, _ args: [String], env: [String: String] = [:], timeout: TimeInterval = 120) async -> ShellResult {
        await withCheckedContinuation { c in
            DispatchQueue.global(qos: .utility).async {
                c.resume(returning: runSync(exe, args, env: env, path: path, timeout: timeout))
            }
        }
    }

    static func runSync(_ exe: String, _ args: [String], env: [String: String] = [:], path: String, timeout: TimeInterval) -> ShellResult {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exe)
        p.arguments = args
        var e = ProcessInfo.processInfo.environment
        e["PATH"] = path
        e["HOMEBREW_NO_AUTO_UPDATE"] = "1"; e["HOMEBREW_NO_ANALYTICS"] = "1"; e["HOMEBREW_NO_ENV_HINTS"] = "1"
        e["HOMEBREW_NO_INSTALL_CLEANUP"] = "1"; e["NO_COLOR"] = "1"
        for (k, v) in env { e[k] = v }
        p.environment = e
        p.standardInput = FileHandle.nullDevice
        let out = Pipe(), err = Pipe()
        p.standardOutput = out; p.standardError = err
        do { try p.run() } catch { return ShellResult(status: -1, stdout: "", stderr: "\(error)", timedOut: false) }

        // Drain both pipes concurrently so a chatty process can't fill a buffer and block.
        let o = Buffer(), r = Buffer()
        let g = DispatchGroup()
        g.enter(); DispatchQueue.global().async { o.data = out.fileHandleForReading.readDataToEndOfFile(); g.leave() }
        g.enter(); DispatchQueue.global().async { r.data = err.fileHandleForReading.readDataToEndOfFile(); g.leave() }
        var timedOut = false
        let deadline = DispatchTime.now() + timeout
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async { p.waitUntilExit(); done.signal() }
        if done.wait(timeout: deadline) == .timedOut { timedOut = true; p.terminate(); _ = done.wait(timeout: .now() + 3) }
        _ = g.wait(timeout: .now() + 5)
        return ShellResult(status: p.terminationStatus, stdout: String(decoding: o.data, as: UTF8.self), stderr: String(decoding: r.data, as: UTF8.self), timedOut: timedOut)
    }
}

// MARK: - HTTP

public struct HTTPError: Error, CustomStringConvertible {
    public var status: Int
    public var url: String
    public var description: String { "HTTP \(status) from \(URL(string: url)?.host ?? url)" }
}

enum FeedError: Error, CustomStringConvertible {
    case invalid(String)
    var description: String { switch self { case .invalid(let detail): return "Invalid feed response: " + detail } }
}

enum DownloadError: Error, Equatable {
    case tooLarge(Int)
}

public enum HTTP {
    // Large indexes opt into a larger finite allowance; ordinary JSON responses stay bounded.
    public static let defaultMaxBytes = 32 * 1024 * 1024

    public static func get(_ url: String, headers: [String: String] = [:], maxBytes: Int = defaultMaxBytes) async throws -> Data {
        try await send(url, method: "GET", body: nil, headers: headers, maxBytes: maxBytes)
    }
    public static func postJSON(_ url: String, _ body: Data) async throws -> Data {
        try await send(url, method: "POST", body: body, headers: ["Content-Type": "application/json"])
    }

    static func send(_ url: String, method: String, body: Data?, headers: [String: String],
                     maxBytes: Int = defaultMaxBytes, configuration: URLSessionConfiguration? = nil) async throws -> Data {
        guard let u = URL(string: url), ["https", "http"].contains(u.scheme?.lowercased() ?? ""), maxBytes > 0 else {
            throw HTTPError(status: 0, url: url)
        }
        var req = URLRequest(url: u)
        req.httpMethod = method
        req.httpBody = body
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        let c = configuration ?? URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = 60
        c.timeoutIntervalForResource = 300
        c.httpAdditionalHeaders = ["User-Agent": "Heimdall/1.0 (macOS user-level vulnerability scanner)"]
        let receiver = BoundedDownload(maxBytes: maxBytes)
        let session = URLSession(configuration: c, delegate: receiver, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        return try await withCheckedThrowingContinuation { continuation in
            receiver.continuation = continuation
            session.dataTask(with: req).resume()
        }
    }
}

/// URLSession delivers these callbacks serially. Check both the advertised size and the
/// actual decoded bytes, so chunked, compressed, or misleading responses cannot bypass it.
private final class BoundedDownload: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    let maxBytes: Int
    var data = Data()
    var failure: Error?
    var continuation: CheckedContinuation<Data, Error>?

    init(maxBytes: Int) { self.maxBytes = maxBytes }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        if !(200..<300).contains(status) {
            failure = HTTPError(status: status, url: response.url?.absoluteString ?? "")
        } else if response.expectedContentLength > Int64(maxBytes) {
            failure = DownloadError.tooLarge(maxBytes)
        }
        completionHandler(failure == nil ? .allow : .cancel)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive chunk: Data) {
        guard failure == nil else { return }
        guard chunk.count <= maxBytes - data.count else {
            failure = DownloadError.tooLarge(maxBytes)
            data.removeAll()
            dataTask.cancel()
            return
        }
        data.append(chunk)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error = failure ?? error { continuation?.resume(throwing: error) }
        else { continuation?.resume(returning: data) }
        continuation = nil
    }
}

// MARK: - Disk cache

/// Small JSON/blob cache under ~/Library/Caches/Heimdall with per-entry age checks.
public struct DiskCache: Sendable {
    public let dir: URL
    public init(_ name: String) { dir = Paths.ensure(Paths.cache.appendingPathComponent(name, isDirectory: true)) }

    init(directory: URL) { dir = Paths.ensure(directory) }

    func url(_ key: String) -> URL {
        let safe = key.map { $0.isLetter || $0.isNumber || "-_.".contains($0) ? $0 : "_" }
        var name = String(safe)
        if name.count > 150 { name = String(name.prefix(110)) + "_" + stableHash(key) }
        return dir.appendingPathComponent(name)
    }
    public func age(_ key: String) -> TimeInterval? {
        FS.mtime(url(key).path).map { Date().timeIntervalSince($0) }
    }
    public func data(_ key: String, maxAge: TimeInterval? = nil) -> Data? {
        if let maxAge, let a = age(key), a > maxAge { return nil }
        return try? Data(contentsOf: url(key))
    }
    public func store(_ key: String, _ data: Data) { try? data.write(to: url(key), options: .atomic) }

    public func get<T: Decodable>(_ key: String, _ type: T.Type, maxAge: TimeInterval? = nil) -> T? {
        data(key, maxAge: maxAge).flatMap { try? JSONCoding.decoder.decode(T.self, from: $0) }
    }
    public func put<T: Encodable>(_ key: String, _ value: T) {
        if let d = try? JSONCoding.encoder.encode(value) { store(key, d) }
    }
}

public enum JSONCoding {
    public static let encoder: JSONEncoder = { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; e.outputFormatting = [.sortedKeys]; return e }()
    public static let pretty: JSONEncoder = { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; e.outputFormatting = [.sortedKeys, .prettyPrinted]; return e }()
    public static let decoder: JSONDecoder = { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d }()
}

func jsonObject(_ d: Data?) -> Any? { d.flatMap { try? JSONSerialization.jsonObject(with: $0) } }

let isoParser: ISO8601DateFormatter = { let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; return f }()
let isoPlain = ISO8601DateFormatter()
public func parseDate(_ s: String?) -> Date? {
    guard let s, !s.isEmpty else { return nil }
    if let d = isoParser.date(from: s) ?? isoPlain.date(from: s) { return d }
    // NVD omits the zone: "2024-05-14T15:44:12.123"
    let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.timeZone = TimeZone(identifier: "UTC")
    for fmt in ["yyyy-MM-dd'T'HH:mm:ss.SSS", "yyyy-MM-dd'T'HH:mm:ss", "yyyy-MM-dd"] {
        f.dateFormat = fmt
        if let d = f.date(from: s) { return d }
    }
    return nil
}

/// Run `body` over `items` with at most `width` in flight.
func concurrentMap<T: Sendable, R: Sendable>(_ items: [T], width: Int, _ body: @escaping @Sendable (T) async -> R) async -> [R] {
    var results = [R?](repeating: nil, count: items.count)
    await withTaskGroup(of: (Int, R).self) { g in
        var next = 0
        for _ in 0..<min(width, items.count) { let i = next; next += 1; g.addTask { (i, await body(items[i])) } }
        while let (i, r) = await g.next() {
            results[i] = r
            if next < items.count { let j = next; next += 1; g.addTask { (j, await body(items[j])) } }
        }
    }
    return results.compactMap { $0 }
}

/// FNV-1a, base 36 — stable across launches (Swift's hashValue is seeded per process).
public func stableHash(_ s: String) -> String {
    var h: UInt64 = 0xcbf29ce484222325
    for b in s.utf8 { h ^= UInt64(b); h = h &* 0x100000001b3 }
    return String(h, radix: 36)
}
