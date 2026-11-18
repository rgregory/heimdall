import Foundation

/// Where an installed piece of software came from. Each one maps to a matching strategy.
public enum Ecosystem: String, Codable, CaseIterable, Sendable, Comparable {
    case macos, app, homebrew, cask, pypi, npm, crates, rubygems, go, browserExtension

    public var title: String {
        switch self {
        case .macos: return "macOS & Safari"
        case .app: return "Applications"
        case .homebrew: return "Homebrew"
        case .cask: return "Homebrew Casks"
        case .pypi: return "Python"
        case .npm: return "Node (npm)"
        case .crates: return "Rust (cargo)"
        case .rubygems: return "Ruby gems"
        case .go: return "Go binaries"
        case .browserExtension: return "Browser extensions"
        }
    }
    /// OSV.dev ecosystem name, when OSV is the matcher.
    public var osvName: String? {
        switch self {
        case .pypi: return "PyPI"
        case .npm: return "npm"
        case .crates: return "crates.io"
        case .rubygems: return "RubyGems"
        case .go: return "Go"
        default: return nil
        }
    }
    /// Front-page grouping.
    public var desk: Desk {
        switch self {
        case .macos: return .system
        case .app, .cask, .browserExtension: return .apps
        case .homebrew: return .homebrew
        case .pypi, .npm, .crates, .rubygems, .go: return .languages
        }
    }
    public static func < (a: Ecosystem, b: Ecosystem) -> Bool {
        allCases.firstIndex(of: a)! < allCases.firstIndex(of: b)!
    }
}

/// The newspaper's "desks" — sections of the front page.
public enum Desk: String, Codable, CaseIterable, Sendable {
    case system, apps, homebrew, languages
    public var title: String {
        switch self {
        case .system: return "The System"
        case .apps: return "Applications"
        case .homebrew: return "Homebrew"
        case .languages: return "Language Packages"
        }
    }
}

/// Whether a vulnerable thing is actually reachable on this Mac: running now, started by
/// launchd, or listening on a socket. Read from the account's own view of the machine, so an
/// answer of "no" means "not while this scan was running" rather than "never".
public struct Exposure: Codable, Hashable, Sendable {
    public var running = false
    public var autostart = false
    public var ports: [Int] = []
    /// How it was seen, for the detail view: the process path, the launchd label.
    public var notes: [String] = []

    public init() {}

    public var listening: Bool { !ports.isEmpty }
    public var any: Bool { running || autostart || listening }
    public var summary: String {
        var parts: [String] = []
        if listening { parts.append("listening on " + ports.map(String.init).joined(separator: ", ")) }
        if running { parts.append("running") }
        if autostart { parts.append("started by launchd") }
        return parts.isEmpty ? "not running when scanned" : parts.joined(separator: " · ")
    }
}

/// Software nobody is going to fix: deprecated or disabled in Homebrew, withdrawn from its
/// registry, or a runtime past the end of its own maintainers' support. An upgrade command would
/// be the wrong advice, so these carry their own.
public struct Maintenance: Codable, Hashable, Sendable {
    public enum State: String, Codable, Sendable {
        case deprecated, disabled, withdrawn, endOfLife

        public var title: String {
            switch self {
            case .deprecated: return "Deprecated"
            case .disabled: return "Disabled"
            case .withdrawn: return "Withdrawn"
            case .endOfLife: return "End of life"
            }
        }
    }
    public var state: State
    /// What the source said, in its words where it has them.
    public var reason: String = ""
    /// "brew info", "npm registry", "PyPI", "crates.io", "release calendar".
    public var source: String = ""
    public var since: Date? = nil
    /// What to use instead, when the source names something.
    public var replacement: String? = nil

    public init(state: State, reason: String = "", source: String = "", since: Date? = nil, replacement: String? = nil) {
        self.state = state; self.reason = reason; self.source = source; self.since = since; self.replacement = replacement
    }

    /// Deprecated is a warning about the future; the rest mean no fixed release is ever coming,
    /// which makes removal the fix rather than a wait.
    public var terminal: Bool { state != .deprecated }
}

public struct Package: Codable, Hashable, Identifiable, Sendable {
    public var ecosystem: Ecosystem
    public var name: String
    public var version: String
    /// Where it lives on disk (bundle, keg, site-packages, binary).
    public var location: String = ""
    /// Human description of how it was found ("brew info", "site-packages", "Info.plist").
    public var source: String = ""
    public var bundleID: String? = nil
    /// Upstream git repository (Homebrew formulae), used for OSV's GIT ecosystem.
    public var repo: String? = nil
    /// Homebrew cask token that installed this app, when known.
    public var cask: String? = nil
    /// Installed from the Mac App Store.
    public var appStore: Bool = false
    /// For Go module deps and nested npm deps: the binary/package that carries this one.
    public var parent: String? = nil
    public var modified: Date? = nil
    /// A newer version is available (Homebrew, Sparkle feed, App Store or the cask index).
    public var outdated: Bool = false
    /// The newest version seen, and where it came from.
    public var latest: String? = nil
    public var latestSource: String? = nil
    /// CFBundleVersion (apps): the build number vendors like Microsoft publish fixes against.
    public var build: String? = nil
    /// Sparkle appcast URL from Info.plist.
    public var feedURL: String? = nil
    /// Which browser a browser extension belongs to.
    public var browser: String? = nil
    /// Go binaries: the Homebrew formula or app bundle that installed the binary.
    public var brewFormula: String? = nil
    public var ownerApp: String? = nil
    /// A product that drops helper binaries outside an .app bundle — "/Library/Application
    /// Support/fuse-t/bin/go-nfsv4" belongs to fuse-t, which is what you actually update.
    public var ownerProduct: String? = nil
    /// Whether this is reachable right now: running, started by launchd, listening. nil means the
    /// question can't be answered for this kind of package (a library inside an interpreter).
    public var exposure: Exposure? = nil
    /// Set when nothing is ever going to fix this one.
    public var maintenance: Maintenance? = nil
    /// Explicit matcher outcome. nil in reports saved before coverage tracking.
    public var coverage: PackageCoverage? = nil

    public var id: String { "\(ecosystem.rawValue):\(parent.map { $0 + ">" } ?? "")\(name)@\(version)@\(location)" }

    public init(ecosystem: Ecosystem, name: String, version: String, location: String = "", source: String = "") {
        self.ecosystem = ecosystem; self.name = name; self.version = version; self.location = location; self.source = source
    }

    public var displayName: String { parent.map { "\(name) (in \($0))" } ?? name }
}

public enum Severity: String, Codable, CaseIterable, Sendable, Comparable {
    case critical, high, medium, low, none, unknown

    public var rank: Int {
        switch self { case .critical: return 5; case .high: return 4; case .medium: return 3; case .low: return 2; case .none: return 1; case .unknown: return 0 }
    }
    public static func < (a: Severity, b: Severity) -> Bool { a.rank < b.rank }
    public var title: String { rawValue.capitalized }

    public init(score: Double) {
        switch score {
        case ..<0.1: self = .none
        case ..<4.0: self = .low
        case ..<7.0: self = .medium
        case ..<9.0: self = .high
        default: self = .critical
        }
    }
    public init(label: String) {
        switch label.uppercased() {
        case "CRITICAL": self = .critical
        case "HIGH", "IMPORTANT": self = .high
        case "MEDIUM", "MODERATE": self = .medium
        case "LOW": self = .low
        case "NONE": self = .none
        default: self = .unknown
        }
    }
}

/// One row of CISA's Known Exploited Vulnerabilities catalog.
public struct KEVEntry: Codable, Hashable, Sendable {
    public var cveID: String
    public var vendorProject: String
    public var product: String
    public var vulnerabilityName: String
    public var dateAdded: String
    public var shortDescription: String
    public var requiredAction: String
    public var dueDate: String
    public var knownRansomwareCampaignUse: String
    /// Which list says it's exploited: nil means CISA KEV; otherwise "VulnCheck KEV", "EUVD", "MSRC",
    /// "CISA SSVC" or "Malicious extension list".
    public var source: String? = nil

    public var ransomware: Bool { knownRansomwareCampaignUse.lowercased() == "known" }
    public var listName: String { source ?? "CISA KEV" }

    public init(cveID: String, vendorProject: String, product: String, vulnerabilityName: String, dateAdded: String,
                shortDescription: String, requiredAction: String, dueDate: String, knownRansomwareCampaignUse: String, source: String? = nil) {
        self.cveID = cveID; self.vendorProject = vendorProject; self.product = product; self.vulnerabilityName = vulnerabilityName
        self.dateAdded = dateAdded; self.shortDescription = shortDescription; self.requiredAction = requiredAction
        self.dueDate = dueDate; self.knownRansomwareCampaignUse = knownRansomwareCampaignUse; self.source = source
    }
}

public enum Confidence: String, Codable, Sendable {
    /// Installed version falls inside a published affected range.
    case versionMatch
    /// Inferred (e.g. KEV entry newer than the app bundle, or no machine-readable range).
    case heuristic
}

public struct Vulnerability: Codable, Hashable, Identifiable, Sendable {
    /// OSV id (GHSA-…, PYSEC-…, GO-…) or CVE id.
    public var id: String
    public var aliases: [String] = []
    public var summary: String = ""
    public var severity: Severity = .unknown
    public var cvss: Double? = nil
    public var vector: String? = nil
    public var published: Date? = nil
    public var fixed: [String] = []
    public var references: [String] = []
    public var kev: KEVEntry? = nil
    public var epss: Double? = nil
    public var epssPercentile: Double? = nil
    /// "OSV", "NVD", "brew vulns", "Apple + KEV".
    public var source: String = ""
    public var confidence: Confidence = .versionMatch
    /// Public exploit code or templates exist: "Exploit-DB", "Metasploit", "nuclei".
    public var publicExploits: [String]? = nil

    public init(id: String) { self.id = id }
    public var hasPublicExploit: Bool { !(publicExploits ?? []).isEmpty }

    public var cves: [String] { ([id] + aliases).filter { $0.hasPrefix("CVE-") }.uniqued() }
    /// The id a person would search for: the CVE when there is one.
    public var headlineID: String { cves.first ?? id }
    public var isKEV: Bool { kev != nil }

    /// Sort key: exploited first, then severity, then EPSS.
    public var priority: Double {
        (isKEV ? 1000 : 0) + (kev?.ransomware == true ? 250 : 0) + (hasPublicExploit ? 60 : 0)
            + Double(severity.rank) * 100 + (cvss ?? 0) * 5 + (epss ?? 0) * 50
    }
}

/// A package and the vulnerabilities that apply to it.
public struct Finding: Codable, Hashable, Identifiable, Sendable {
    public var package: Package
    public var vulns: [Vulnerability]
    public var fixHint: String = ""
    /// No released version fixes these yet (only an upstream commit, or nothing newer exists).
    public var awaitingRelease: Bool? = nil
    /// "How to fix it": ordered steps, commands or plain sentences.
    public var fixSteps: [String]? = nil
    /// The first scan that saw this, from the history file. nil on a Mac with no history yet.
    public var firstSeen: Date? = nil

    public var id: String { package.id }
    /// Whole days this has been open here. Rounded down, so "today" reads as 0 rather than 1.
    public var ageDays: Int? {
        firstSeen.map { max(0, Int(Date().timeIntervalSince($0) / 86400)) }
    }
    public var kevCount: Int { vulns.filter(\.isKEV).count }
    public var topSeverity: Severity { vulns.map(\.severity).max() ?? .unknown }
    /// What the advisories say, on their own.
    public var priority: Double { vulns.map(\.priority).max() ?? 0 }
    public var ransomware: Bool { vulns.contains { $0.kev?.ransomware == true } }

    /// What the advisories say, adjusted for this Mac: whether there is anything to install,
    /// whether anyone is ever going to ship one, whether you run this code at all, and how long
    /// it has been sitting here. Computed, never stored, so it tracks the latest advice.
    public var risk: Risk {
        var score = priority
        var factors: [String] = []
        if kevCount > 0 { factors.append("exploited in the wild") }
        if ransomware { factors.append("used in ransomware campaigns") }
        if vulns.contains(where: \.hasPublicExploit) { factors.append("public exploit code") }
        if let e = vulns.compactMap(\.epss).max(), e >= 0.05 {
            factors.append("\(Int((e * 100).rounded()))% chance of attack in 30 days")
        }
        // Three different situations, not two: a command to run, a wait for someone else to ship,
        // and a thing that will never be fixed. The last one is work you can do tonight — it just
        // isn't an upgrade — so it ranks with the fixable rather than with the stuck.
        let abandoned = package.maintenance?.terminal == true
        let blocked = awaitingRelease == true && !abandoned
        if abandoned {
            score += 120
            factors.append("no fix is ever coming — \(package.maintenance?.state.title.lowercased() ?? "unmaintained")")
        } else if blocked {
            score -= 400
            factors.append("nothing to install yet")
        } else if !fixHint.isEmpty {
            score += 150
            factors.append("fixable now")
        }
        if package.maintenance?.state == .deprecated {
            score += 20
            factors.append("deprecated upstream")
        }
        // Reachability. The same flaw in something listening on a socket and in something that
        // hasn't run since it was installed are not the same evening's work.
        if let e = package.exposure {
            if e.listening {
                score += 120
                factors.append("listening on " + e.ports.map(String.init).joined(separator: ", "))
            }
            if e.running { score += 70; factors.append("running right now") }
            if e.autostart { score += 40; factors.append("started by launchd") }
            if !e.any { score -= 40; factors.append("not running when scanned") }
        }
        // Something bundled inside another program: you don't invoke it, and the vulnerable code
        // may not even be reached. Still real, just not the first thing to spend an evening on.
        if package.parent != nil {
            score -= 60
            factors.append("bundled inside \(package.parent ?? "another program")")
        }
        // How long it has been here. An advisory that appeared this morning and one that has been
        // open for a month are the same advisory and not the same problem.
        if let days = ageDays, days >= 7 {
            score += min(80, Double(days) * 2)
            factors.append("open for \(days) days")
        }
        return Risk(score: score, factors: factors, blocked: blocked, abandoned: abandoned)
    }
}

/// A finding's rank, and the reasons behind it — shown on the row so the order is never a mystery.
public struct Risk: Sendable, Hashable {
    public var score: Double
    public var factors: [String]
    /// Exploited or severe, but nothing to install: it belongs on the list, not on tonight's list.
    public var blocked: Bool
    /// No released version will ever fix this, so the fix is to remove or replace it.
    public var abandoned: Bool = false
}

public struct SourceStatus: Codable, Hashable, Identifiable, Sendable {
    public enum State: String, Codable, Sendable { case ok, warning, failed, skipped }
    public var name: String
    public var state: State
    public var detail: String
    public var count: Int? = nil
    public var updated: Date? = nil
    public var id: String { name }

    public init(name: String, state: State, detail: String, count: Int? = nil, updated: Date? = nil) {
        self.name = name; self.state = state; self.detail = detail; self.count = count; self.updated = updated
    }
}

/// macOS release posture against Apple's security-release index.
public struct SystemPosture: Codable, Hashable, Sendable {
    public var osVersion: String = ""
    public var osBuild: String = ""
    public var latestInLine: String? = nil
    public var releasesBehind: [AppleRelease] = []
    public var safariVersion: String? = nil
    public var safariLatest: String? = nil
    public var hostName: String = ""
    public var model: String = ""
}

public struct AppleRelease: Codable, Hashable, Sendable {
    public var name: String
    public var product: String
    public var version: String
    public var date: Date
    public var link: String
    public var hasCVEs: Bool
}

public struct ScanReport: Codable, Sendable {
    public var generated: Date
    public var duration: TimeInterval = 0
    public var posture: SystemPosture
    public var packages: [Package]
    public var findings: [Finding]
    public var sources: [SourceStatus]
    public var kevCatalogVersion: String? = nil
    /// An interim report sent while lookups are still running.
    public var partial: Bool = false
    /// A year of CISA KEV listings, marked by relevance to this Mac.
    public var timeline: [TimelineEntry]? = nil
    /// Security news from the last 30 days, matched to this Mac.
    public var news: [NewsItem]? = nil
    /// Inventory scope used to distinguish removal from a disabled collector.
    public var scanOptions: ScanOptions? = nil

    public init(generated: Date, posture: SystemPosture, packages: [Package], findings: [Finding], sources: [SourceStatus]) {
        self.generated = generated; self.posture = posture; self.packages = packages; self.findings = findings; self.sources = sources
    }

    public var allVulns: [(Finding, Vulnerability)] { findings.flatMap { f in f.vulns.map { (f, $0) } } }
    /// Exploited in the wild, or a malicious extension: worth turning the icon red for.
    public var urgent: Bool { kevCount > 0 }
    public var outdatedPackages: [Package] { packages.filter { $0.outdated && $0.latest != nil } }
    public var kevFindings: [Finding] { findings.filter { $0.kevCount > 0 }.sorted { $0.risk.score > $1.risk.score } }
    /// Installed things no release will ever fix, whether or not an advisory names them yet.
    public var unmaintained: [Package] {
        packages.filter { $0.maintenance?.terminal == true }.sorted { $0.name.lowercased() < $1.name.lowercased() }
    }
    /// Findings whose fix is removal rather than an upgrade.
    public var abandonedFindings: [Finding] { findings.filter { $0.risk.abandoned }.sorted { $0.risk.score > $1.risk.score } }
    /// Findings on something running, started by launchd or listening right now.
    public var reachableFindings: [Finding] { findings.filter { $0.package.exposure?.any == true }.sorted { $0.risk.score > $1.risk.score } }
    public var kevCount: Int { Set(allVulns.filter { $0.1.isKEV }.map { $0.0.id + $0.1.headlineID }).count }
    public func findings(in desk: Desk) -> [Finding] {
        findings.filter { $0.package.ecosystem.desk == desk }.sorted { $0.risk.score > $1.risk.score }
    }
    public func count(_ s: Severity) -> Int { allVulns.filter { $0.1.severity == s }.count }
}

extension Array where Element: Hashable {
    public func uniqued() -> [Element] { var s = Set<Element>(); return filter { s.insert($0).inserted } }
}
