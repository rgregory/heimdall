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
        (isKEV ? 1000 : 0) + (hasPublicExploit ? 60 : 0) + Double(severity.rank) * 100 + (cvss ?? 0) * 5 + (epss ?? 0) * 50
    }
}

/// A package and the vulnerabilities that apply to it.
public struct Finding: Codable, Hashable, Identifiable, Sendable {
    public var package: Package
    public var vulns: [Vulnerability]
    public var fixHint: String = ""
    /// No released version fixes these yet (only an upstream commit, or nothing newer exists).
    public var awaitingRelease: Bool? = nil

    public var id: String { package.id }
    public var kevCount: Int { vulns.filter(\.isKEV).count }
    public var topSeverity: Severity { vulns.map(\.severity).max() ?? .unknown }
    public var priority: Double { vulns.map(\.priority).max() ?? 0 }
    public var ransomware: Bool { vulns.contains { $0.kev?.ransomware == true } }
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

    public init(generated: Date, posture: SystemPosture, packages: [Package], findings: [Finding], sources: [SourceStatus]) {
        self.generated = generated; self.posture = posture; self.packages = packages; self.findings = findings; self.sources = sources
    }

    public var allVulns: [(Finding, Vulnerability)] { findings.flatMap { f in f.vulns.map { (f, $0) } } }
    /// Exploited in the wild, or a malicious extension: worth turning the icon red for.
    public var urgent: Bool { kevCount > 0 }
    public var outdatedPackages: [Package] { packages.filter { $0.outdated && $0.latest != nil } }
    public var kevFindings: [Finding] { findings.filter { $0.kevCount > 0 }.sorted { $0.priority > $1.priority } }
    public var kevCount: Int { Set(allVulns.filter { $0.1.isKEV }.map { $0.0.id + $0.1.headlineID }).count }
    public func findings(in desk: Desk) -> [Finding] {
        findings.filter { $0.package.ecosystem.desk == desk }.sorted { $0.priority > $1.priority }
    }
    public func count(_ s: Severity) -> Int { allVulns.filter { $0.1.severity == s }.count }
}

extension Array where Element: Hashable {
    public func uniqued() -> [Element] { var s = Set<Element>(); return filter { s.insert($0).inserted } }
}
