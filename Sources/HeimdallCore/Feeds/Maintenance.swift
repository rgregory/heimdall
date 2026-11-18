import Foundation

/// Which installed things nobody is going to fix. Heimdall already separates "there is a command
/// to run" from "the fix hasn't shipped yet", and this is the third case: the fix is never
/// coming, because the formula is deprecated, the release was withdrawn from its registry, or the
/// runtime's own maintainers stopped publishing security fixes years ago. The answer to those is
/// to remove or replace the thing, so saying "upgrade" would be wrong in a way that wastes an
/// evening.
public enum MaintenanceCheck {
    // MARK: End-of-life runtimes

    struct EOL: Sendable {
        /// Homebrew formula name, exactly or as a prefix ending in "*".
        let formula: String
        let product: String
        /// The day its own maintainers stopped publishing security fixes, ISO 8601.
        let date: String

        func matches(_ name: String) -> Bool {
            formula.hasSuffix("*") ? name.hasPrefix(String(formula.dropLast())) : name == formula
        }
    }

    /// Dated rather than hardcoded as "old", so an entry only counts from the day it expires and
    /// a table nobody has updated under-reports instead of inventing something. Dates come from
    /// each project's own release calendar.
    static let endOfLife: [EOL] = [
        EOL(formula: "python@2*", product: "Python 2", date: "2020-01-01"),
        EOL(formula: "python@3.6", product: "Python 3.6", date: "2021-12-23"),
        EOL(formula: "python@3.7", product: "Python 3.7", date: "2023-06-27"),
        EOL(formula: "python@3.8", product: "Python 3.8", date: "2024-10-07"),
        EOL(formula: "python@3.9", product: "Python 3.9", date: "2025-10-31"),
        EOL(formula: "python@3.10", product: "Python 3.10", date: "2026-10-31"),
        EOL(formula: "node@12", product: "Node 12", date: "2022-04-30"),
        EOL(formula: "node@14", product: "Node 14", date: "2023-04-30"),
        EOL(formula: "node@16", product: "Node 16", date: "2023-09-11"),
        EOL(formula: "node@18", product: "Node 18", date: "2025-04-30"),
        EOL(formula: "node@20", product: "Node 20", date: "2026-04-30"),
        EOL(formula: "ruby@2*", product: "Ruby 2", date: "2023-03-31"),
        EOL(formula: "ruby@3.0", product: "Ruby 3.0", date: "2024-04-23"),
        EOL(formula: "ruby@3.1", product: "Ruby 3.1", date: "2025-03-31"),
        EOL(formula: "ruby@3.2", product: "Ruby 3.2", date: "2026-03-31"),
        EOL(formula: "openssl@1.0", product: "OpenSSL 1.0.2", date: "2019-12-31"),
        EOL(formula: "openssl@1.1", product: "OpenSSL 1.1.1", date: "2023-09-11"),
        EOL(formula: "php@7*", product: "PHP 7", date: "2022-11-28"),
        EOL(formula: "php@8.0", product: "PHP 8.0", date: "2023-11-26"),
        EOL(formula: "php@8.1", product: "PHP 8.1", date: "2025-12-31"),
        EOL(formula: "postgresql@11", product: "PostgreSQL 11", date: "2023-11-09"),
        EOL(formula: "postgresql@12", product: "PostgreSQL 12", date: "2024-11-14"),
        EOL(formula: "postgresql@13", product: "PostgreSQL 13", date: "2025-11-13"),
    ]

    static let day: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        f.timeZone = TimeZone(identifier: "UTC")
        f.locale = Locale(identifier: "en_US_POSIX")
        return f
    }()

    static let readable: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "d MMMM yyyy"
        f.timeZone = TimeZone(identifier: "UTC")
        f.locale = Locale(identifier: "en_US_POSIX")
        return f
    }()

    /// Free and offline: whatever the collectors already read, plus the release calendars above.
    /// Homebrew's own deprecation flags are set where the formula is read, so this only adds the
    /// end-of-life runtimes.
    @discardableResult
    public static func local(_ packages: inout [Package], now: Date = Date()) -> SourceStatus {
        var found = 0
        for i in packages.indices where packages[i].ecosystem == .homebrew {
            guard packages[i].maintenance == nil else { continue }   // brew's own word comes first
            guard let e = endOfLife.first(where: { $0.matches(packages[i].name) }),
                  let d = day.date(from: e.date), d < now else { continue }
            packages[i].maintenance = Maintenance(
                state: .endOfLife,
                reason: "\(e.product) stopped getting security fixes on \(readable.string(from: d)). Advisories against it stay open.",
                source: "release calendar", since: d)
            found += 1
        }
        let eol = packages.filter { $0.maintenance?.state == .endOfLife }.count
        let brew = packages.filter { $0.maintenance?.state == .deprecated || $0.maintenance?.state == .disabled }.count
        return SourceStatus(name: "Maintenance", state: .ok,
                            detail: "\(brew) deprecated or disabled in Homebrew, \(eol) past end of life",
                            count: brew + eol, updated: Date())
    }

    // MARK: Withdrawn releases

    /// Registries know things the installed copy can't: that a release was yanked after it
    /// shipped, or that the package was deprecated with a note pointing somewhere else. Asked
    /// only for packages that already have an advisory, so a scan adds a few dozen small requests
    /// rather than one per installed package.
    public static let maxLookups = 60

    @discardableResult
    public static func registry(_ r: inout ScanReport, offline: Bool) async -> SourceStatus {
        if offline {
            return SourceStatus(name: "Withdrawn releases", state: .skipped, detail: "offline; registries not asked")
        }
        let cache = DiskCache("maintenance")
        let wanted = r.findings
            .map(\.package)
            .filter { $0.maintenance == nil && supported($0.ecosystem) && !$0.name.isEmpty && !$0.version.isEmpty }
        var seen = Set<String>(), queue: [Package] = []
        for p in wanted where seen.insert("\(p.ecosystem.rawValue)|\(p.name)|\(p.version)").inserted { queue.append(p) }
        guard !queue.isEmpty else {
            return SourceStatus(name: "Withdrawn releases", state: .ok, detail: "nothing to ask about", count: 0, updated: Date())
        }
        let asked = Array(queue.prefix(maxLookups))
        var answers: [String: Maintenance] = [:]
        var failures = 0
        for p in asked {
            let key = "\(p.ecosystem.rawValue)-\(p.name)-\(p.version).json".replacingOccurrences(of: "/", with: "_")
            if let hit = cache.get(key, Answer.self, maxAge: 7 * 86400) {
                if let m = hit.maintenance { answers[identity(p)] = m }
                continue
            }
            do {
                let m = try await ask(p)
                cache.put(key, Answer(maintenance: m))
                if let m { answers[identity(p)] = m }
            } catch {
                failures += 1
            }
        }
        for i in r.packages.indices {
            if let m = answers[identity(r.packages[i])], r.packages[i].maintenance == nil { r.packages[i].maintenance = m }
        }
        for i in r.findings.indices {
            if let m = answers[identity(r.findings[i].package)], r.findings[i].package.maintenance == nil {
                r.findings[i].package.maintenance = m
            }
        }
        var detail = "\(asked.count) package\(asked.count == 1 ? "" : "s") checked against npm, PyPI and crates.io; \(answers.count) withdrawn or deprecated"
        if queue.count > asked.count { detail += "; \(queue.count - asked.count) left for the next scan" }
        if failures > 0 { detail += "; \(failures) no answer" }
        return SourceStatus(name: "Withdrawn releases", state: failures > 0 ? .warning : .ok, detail: detail,
                            count: answers.count, updated: Date())
    }

    /// A yank is about one release, so an answer stays pinned to the version it was asked about.
    static func identity(_ p: Package) -> String { "\(p.ecosystem.rawValue)|\(p.name)|\(p.version)" }

    /// Cached as a box so "asked, and it is fine" is remembered as well as a hit.
    struct Answer: Codable { var maintenance: Maintenance? }

    static func supported(_ e: Ecosystem) -> Bool { e == .npm || e == .pypi || e == .crates }

    static func ask(_ p: Package) async throws -> Maintenance? {
        switch p.ecosystem {
        case .npm:
            let name = p.name.replacingOccurrences(of: "/", with: "%2F")
            let j = jsonObject(try await HTTP.get("https://registry.npmjs.org/\(name)/\(p.version)", maxBytes: 4 << 20)) as? [String: Any] ?? [:]
            guard let note = j["deprecated"] as? String else { return nil }
            return Maintenance(state: .deprecated, reason: note.isEmpty ? "The publisher marked this version deprecated." : note,
                               source: "npm registry", replacement: pointer(in: note))
        case .pypi:
            let j = jsonObject(try await HTTP.get("https://pypi.org/pypi/\(p.name)/\(p.version)/json", maxBytes: 8 << 20)) as? [String: Any] ?? [:]
            let info = j["info"] as? [String: Any] ?? [:]
            if info["yanked"] as? Bool == true {
                let why = (info["yanked_reason"] as? String)?.trimmed ?? ""
                return Maintenance(state: .withdrawn, reason: why.isEmpty ? "This release was yanked from PyPI after it shipped." : why,
                                   source: "PyPI")
            }
            if (info["classifiers"] as? [String] ?? []).contains(where: { $0.contains("Development Status :: 7 - Inactive") }) {
                return Maintenance(state: .deprecated, reason: "The author classifies this project as inactive.", source: "PyPI")
            }
            return nil
        case .crates:
            let j = jsonObject(try await HTTP.get("https://crates.io/api/v1/crates/\(p.name)/\(p.version)", maxBytes: 2 << 20)) as? [String: Any] ?? [:]
            let v = j["version"] as? [String: Any] ?? [:]
            guard v["yanked"] as? Bool == true else { return nil }
            return Maintenance(state: .withdrawn, reason: "This release was yanked from crates.io after it shipped.", source: "crates.io")
        default:
            return nil
        }
    }

    /// Deprecation notes usually name the replacement. Worth pulling out, since it is the whole
    /// answer when there is one.
    static func pointer(in note: String) -> String? {
        guard let m = note.firstMatch("(?:use|see|moved to|replaced by|switch to)\\s+([@A-Za-z0-9._/-]{2,60})", options: .caseInsensitive) else { return nil }
        return m[1]
    }
}
