import Foundation

/// How long each flaw has been here. The report store keeps the last two scans, which is enough
/// to say what changed since yesterday and not enough to say what has been sitting open since
/// August, so first sightings go in a file of their own and stay there. Age is a fact about this
/// Mac rather than about the advisory: the same CVE is a different proposition on its first
/// morning and in its fourth week.
public enum History {
    struct File: Codable {
        var firstSeen: [String: Date] = [:]
        var lastSeen: [String: Date] = [:]
        var scans: [Scan] = []
    }

    /// One row per scan, for the trend. Small on purpose: counts, not copies of the report.
    public struct Scan: Codable, Hashable, Sendable, Identifiable {
        public var date: Date
        public var packages: Int
        public var findings: Int
        public var exploited: Int
        public var id: Date { date }
    }

    static var url: URL { Paths.support.appendingPathComponent("history.json") }
    /// Keep roughly a year of twice-daily scans, and forget a finding that has been gone a year.
    static let maxScans = 800
    static let forget: TimeInterval = 365 * 86400
    /// Two scans within this of each other are the same sitting; only the first gets a row.
    static let minScanGap: TimeInterval = 3600

    /// A package's identity without its version, so an advisory that survives a patch release is
    /// the same open problem rather than a new one each time the version moves.
    public static func key(_ p: Package, _ v: Vulnerability) -> String {
        "\(p.ecosystem.rawValue)|\(p.parent ?? "")|\(p.name)|\(v.headlineID)"
    }

    static func load() -> File {
        (try? Data(contentsOf: url)).flatMap { try? JSONCoding.decoder.decode(File.self, from: $0) } ?? File()
    }

    static func write(_ f: File) {
        if let d = try? JSONCoding.encoder.encode(f) { try? d.write(to: url, options: .atomic) }
    }

    /// Fill in `firstSeen` from what's already on disk. Read-only and cheap, so it is safe to
    /// call on the interim reports a scan sends while it is still running.
    public static func stamp(_ r: inout ScanReport) {
        let f = load()
        guard !f.firstSeen.isEmpty else { return }
        apply(&r, f.firstSeen)
    }

    static func apply(_ r: inout ScanReport, _ dates: [String: Date]) {
        for i in r.findings.indices {
            let p = r.findings[i].package
            r.findings[i].firstSeen = r.findings[i].vulns.compactMap { dates[key(p, $0)] }.min()
        }
    }

    /// Record a finished scan: anything new gets this scan's date, anything seen again has its
    /// last sighting bumped, and the report comes back stamped. Never records a partial report —
    /// a finding the slow lookups haven't produced yet has not gone away.
    public static func record(_ r: inout ScanReport) {
        guard !r.partial else { stamp(&r); return }
        var f = load()
        let now = r.generated
        for (finding, vuln) in r.allVulns {
            let k = key(finding.package, vuln)
            if f.firstSeen[k] == nil { f.firstSeen[k] = now }
            f.lastSeen[k] = now
        }
        let cutoff = now.addingTimeInterval(-forget)
        for (k, seen) in f.lastSeen where seen < cutoff {
            f.lastSeen[k] = nil
            f.firstSeen[k] = nil
        }
        if (f.scans.last?.date).map({ now.timeIntervalSince($0) >= minScanGap }) ?? true {
            f.scans.append(Scan(date: now, packages: r.packages.count, findings: r.findings.count, exploited: r.kevCount))
            if f.scans.count > maxScans { f.scans.removeFirst(f.scans.count - maxScans) }
        }
        write(f)
        apply(&r, f.firstSeen)
    }

    /// Scan rows, oldest first.
    public static func trend() -> [Scan] { load().scans }
}
