import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// What is worth interrupting someone for after a scan: an exploited advisory that wasn't there
/// last time and hasn't been deferred. Everything else waits for the window to be opened.
public enum Alerts {
    public struct Item: Sendable, Hashable {
        public var package: String
        public var advisory: String
        public var fixable: Bool
        public var ransomware: Bool
    }

    public static func newExploited(current: ScanReport, previous: ScanReport?, exceptions: [FindingException], now: Date = Date()) -> [Item] {
        // A partial report is still filling in; judging it would announce things twice.
        guard !current.partial else { return [] }
        func key(_ f: Finding, _ v: Vulnerability) -> String { f.package.installationKey + "|" + v.headlineID }
        let before = Set((previous?.allVulns ?? []).filter { $0.1.isKEV }.map { key($0.0, $0.1) })
        var seen = Set<String>()
        var out: [Item] = []
        for (f, v) in current.allVulns.sorted(by: { $0.1.priority > $1.1.priority }) where v.isKEV {
            let k = key(f, v)
            guard !before.contains(k), seen.insert(k).inserted else { continue }
            guard !exceptions.contains(where: { $0.applies(to: f.package, vulnerability: v, now: now) }) else { continue }
            out.append(Item(package: f.package.displayName, advisory: v.headlineID,
                            fixable: !(f.risk.blocked), ransomware: v.kev?.ransomware == true))
        }
        return out
    }

    /// Notification text for a set of new exploited findings, or nil when there is nothing to say.
    public static func message(_ items: [Item]) -> (title: String, body: String)? {
        guard let first = items.first else { return nil }
        let fixable = items.filter(\.fixable).count
        let title = items.count == 1 ? "Exploited: \(first.package)" : "\(items.count) newly exploited findings"
        var body = items.count == 1
            ? "\(first.advisory) is on a known-exploited list."
            : items.prefix(3).map { "\($0.package) (\($0.advisory))" }.joined(separator: ", ") + (items.count > 3 ? ", …" : "")
        if items.contains(where: \.ransomware) { body += " Used in ransomware campaigns." }
        body += fixable == 0 ? " No fix to install yet." : fixable == items.count ? " An update is available." : " \(fixable) can be fixed now."
        return (title, body)
    }
}

/// Is there a newer Heimdall than this one? Asks GitHub's latest-release endpoint once a day.
public enum ReleaseCheck {
    public static let repo = "rgregory/heimdall"
    public struct Release: Codable, Sendable, Equatable { public var version: String; public var url: String }

    public static func parse(_ data: Data) -> Release? {
        guard let o = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let tag = o["tag_name"] as? String, let url = o["html_url"] as? String,
              o["draft"] as? Bool != true, o["prerelease"] as? Bool != true else { return nil }
        var v = tag
        if v.hasPrefix("v") || v.hasPrefix("V") { v.removeFirst() }
        return Release(version: v, url: url)
    }

    public static func newer(_ release: Release?, than installed: String) -> Release? {
        guard let release, !installed.isEmpty, Version.compare(release.version, installed) > 0 else { return nil }
        return release
    }

    /// Cached for a day; offline uses whatever was cached. Nil on any failure (a private repo answers 404).
    public static func latest(offline: Bool) async -> Release? {
        let cache = DiskCache("release")
        if let r = cache.get("latest", Release.self, maxAge: 86400) { return r }
        guard !offline else { return cache.get("latest", Release.self) }
        guard let data = try? await HTTP.get("https://api.github.com/repos/\(repo)/releases/latest",
                                             headers: ["Accept": "application/vnd.github+json"], maxBytes: 1 << 20),
              let r = parse(data) else { return nil }
        cache.put("latest", r)
        return r
    }
}
