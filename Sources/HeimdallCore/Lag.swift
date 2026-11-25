import Foundation

/// How long each flaw spent at each stage, kept so a later stats view has history to read.
/// Four clocks, and the gaps between them are the only honest answer to "how fast is this
/// Mac patched": the advisory appears, upstream ships a fix, Homebrew bottles it, and this
/// Mac installs it. Three of the four are recoverable from public data at any time; the
/// install date is not, because `brew cleanup` deletes the keg receipt it comes from.
public enum Lag {
    public struct Record: Codable, Hashable, Sendable, Identifiable {
        public var ecosystem: String
        /// The formula or package the advisory applied to.
        public var package: String
        /// The version installed when the advisory was open here.
        public var version: String
        public var advisory: String
        /// T0 — the advisory was published.
        public var published: Date?
        /// T0b — CISA listed it as exploited.
        public var kevAdded: Date?
        /// The first released version that fixes it, when one is known.
        public var fixedVersion: String?
        /// T2 — a Homebrew bottle for the fixed version existed.
        public var bottled: Date?
        /// T3 — the version in use here was installed.
        public var installed: Date?
        /// T4 — Heimdall first reported it, and the scan when it stopped appearing.
        public var firstSeen: Date?
        public var resolved: Date?

        public var id: String { "\(ecosystem)|\(package)|\(version)|\(advisory)" }

        /// Days between the advisory and a bottle carrying the fix: how long Homebrew took.
        public var packagingDays: Int? { Self.days(from: published, to: bottled) }
        /// Days a fix sat installable before it was taken. The one you control. `installed`
        /// is when the *vulnerable* version was poured, which is almost always before the fix
        /// was bottled, so the clock runs to the day the advisory stopped appearing — or to
        /// today, while it is still here.
        public var exposureDays: Int? { Self.days(from: bottled, to: resolved ?? Date()) }
        /// Days the advisory was open on this Mac, as Heimdall saw it.
        public var dwellDays: Int? { Self.days(from: firstSeen, to: resolved ?? Date()) }

        static func days(from: Date?, to: Date?) -> Int? {
            guard let from, let to, to >= from else { return nil }
            return Int(to.timeIntervalSince(from) / 86400)
        }
    }

    /// How far behind the installed version of a formula is, measured in days of releases
    /// rather than version numbers. Needs no advisory and no waiting: both dates are public
    /// and historical, so this is populated the first time it runs.
    public struct Freshness: Codable, Hashable, Sendable, Identifiable {
        public var formula: String
        public var installed: String
        public var latest: String
        /// The day the installed version was bottled.
        public var installedBottled: Date?
        /// The day the newest version was bottled.
        public var latestBottled: Date?
        /// When this Mac actually poured the version it is on.
        public var installedHere: Date?
        public var checked: Date

        public var id: String { formula }
        /// Days of released-but-not-installed updates.
        public var behindDays: Int? { Record.days(from: installedBottled, to: latestBottled) }
        /// Days between the fix being installable and this Mac still not having it.
        public var shelfDays: Int? { Record.days(from: latestBottled, to: Date()) }
    }

    /// Decoded by hand on purpose. A synthesized decoder requires every key, defaults and
    /// all, so adding a field silently turns every file written before it into a decode
    /// failure — which here read as "no history" and then overwrote the history.
    struct File: Codable {
        var records: [String: Record] = [:]
        var freshness: [String: Freshness] = [:]

        init() {}

        enum CodingKeys: String, CodingKey { case records, freshness }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            records = (try? c.decodeIfPresent([String: Record].self, forKey: .records)) ?? [:]
            freshness = (try? c.decodeIfPresent([String: Freshness].self, forKey: .freshness)) ?? [:]
        }
    }

    static var url: URL { Paths.support.appendingPathComponent("lag.json") }
    /// Roughly two years of closed records is plenty for a trend; open ones are never dropped.
    static let forget: TimeInterval = 730 * 86400

    static func load() -> File {
        (try? Data(contentsOf: url)).flatMap { try? JSONCoding.decoder.decode(File.self, from: $0) } ?? File()
    }

    static func write(_ f: File) {
        if let d = try? JSONCoding.encoder.encode(f) { try? d.write(to: url, options: .atomic) }
    }

    /// Fold a finished scan into the store: new advisories get a row, rows already there keep
    /// their dates, and anything that has stopped appearing is closed off at this scan.
    public static func record(_ report: ScanReport, bottled: [String: Date] = [:]) {
        guard !report.partial else { return }
        var f = load()
        let now = report.generated
        var present: Set<String> = []
        for (finding, vuln) in report.allVulns {
            let p = finding.package
            let fixed = firstFixedVersion(vuln, above: p.version)
            var r = Record(ecosystem: p.ecosystem.rawValue, package: p.name, version: p.version, advisory: vuln.headlineID)
            present.insert(r.id)
            if var existing = f.records[r.id] {
                // Dates already learned stay put; only what was missing gets filled in.
                existing.published = existing.published ?? vuln.published
                existing.kevAdded = existing.kevAdded ?? kevDate(vuln)
                existing.fixedVersion = existing.fixedVersion ?? fixed
                existing.bottled = existing.bottled ?? fixed.flatMap { bottled["\(p.name)@\($0)"] }
                existing.installed = existing.installed ?? p.installed ?? p.modified
                existing.firstSeen = existing.firstSeen ?? finding.firstSeen ?? now
                existing.resolved = nil
                f.records[r.id] = existing
            } else {
                r.published = vuln.published
                r.kevAdded = kevDate(vuln)
                r.fixedVersion = fixed
                r.bottled = fixed.flatMap { bottled["\(p.name)@\($0)"] }
                r.installed = p.installed ?? p.modified
                r.firstSeen = finding.firstSeen ?? now
                f.records[r.id] = r
            }
        }
        for (key, var r) in f.records where !present.contains(key) && r.resolved == nil {
            r.resolved = now
            f.records[key] = r
        }
        let cutoff = now.addingTimeInterval(-forget)
        for (key, r) in f.records {
            if let resolved = r.resolved, resolved < cutoff { f.records[key] = nil }
        }
        write(f)
    }

    /// Record how far behind each outdated formula is. Called with the dates already
    /// fetched, so this stays a file write.
    public static func recordFreshness(_ rows: [Freshness], checked: Set<String> = []) {
        guard !rows.isEmpty || !checked.isEmpty else { return }
        var f = load()
        for name in checked { f.freshness[name] = nil }
        for r in rows { f.freshness[r.formula] = r }
        write(f)
    }

    /// Drop rows whose formula is gone or whose recorded installed tag is not the keg now on
    /// disk. `installed` maps formula name → exact keg tag ("1.11.1_7").
    public static func pruneFreshness(installed: [String: String]) {
        var f = load()
        let before = f.freshness.count
        f.freshness = f.freshness.filter { name, row in installed[name] == row.installed }
        if f.freshness.count != before { write(f) }
    }

    public static func freshness() -> [Freshness] {
        load().freshness.values.sorted { ($0.behindDays ?? -1) > ($1.behindDays ?? -1) }
    }

    /// Pull in what the history file already knows. Heimdall has been recording when each
    /// advisory first appeared and was last seen since well before this store existed, so
    /// every advisory that came and went in that time is real dwell history — it just lives
    /// in another file. Rows made here carry no version, because history does not keep one.
    public static func backfillFromHistory() {
        var f = load()
        var added = 0
        for (key, first) in History.load().firstSeen {
            // "ecosystem|parent|name|advisory"
            let parts = key.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 4 else { continue }
            var r = Record(ecosystem: parts[0], package: parts[2], version: "", advisory: parts[3])
            let id = r.id
            guard f.records[id] == nil else { continue }
            let last = History.load().lastSeen[key]
            r.firstSeen = first
            // Still in the current scan? Then it is open, and the next record() will own it.
            r.resolved = last.map { Date().timeIntervalSince($0) > 2 * 86400 ? $0 : nil } ?? nil
            f.records[id] = r
            added += 1
        }
        if added > 0 { write(f) }
    }

    /// Every row, newest first by whichever date the row has.
    public static func all() -> [Record] {
        load().records.values.sorted { ($0.firstSeen ?? .distantPast) > ($1.firstSeen ?? .distantPast) }
    }

    /// The Homebrew rows worth a lag stat: a fix was bottled and we know when.
    public static func homebrew() -> [Record] {
        all().filter { $0.ecosystem == Ecosystem.homebrew.rawValue && $0.bottled != nil }
    }

    static func kevDate(_ v: Vulnerability) -> Date? {
        guard let added = v.kev?.dateAdded, !added.isEmpty else { return nil }
        return Bottles.day(added)
    }

    static func firstFixedVersion(_ v: Vulnerability, above version: String) -> String? {
        v.fixed.filter { !$0.hasPrefix("commit") && Version.compare($0, version) > 0 }
            .min(by: { Version.less($0, $1) }) ?? v.fixed.first
    }
}
