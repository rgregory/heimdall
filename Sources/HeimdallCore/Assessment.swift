import Foundation

public struct PackageCoverage: Codable, Hashable, Sendable {
    public enum State: String, Codable, Sendable {
        case checked, noMapping, unavailable, disabled, cached, pending
        public var title: String {
            switch self {
            case .checked: return "Checked"
            case .noMapping: return "No product mapping"
            case .unavailable: return "Lookup unavailable"
            case .disabled: return "Not checked"
            case .cached: return "Cached data only"
            case .pending: return "Still checking"
            }
        }
    }
    public var state: State
    public var detail: String
    public var supportsUpgradeVerification: Bool
    /// Which feed decided this state ("NVD", "OSV.dev", "brew vulns", …). Optional so reports
    /// saved before it existed still decode.
    public var source: String?
    /// Why the lookup came back empty-handed, as a short phrase ("batch query failed",
    /// "no answer (rate-limited or erroring)"). Groups the "unavailable" count by cause.
    public var reason: String?
    public init(_ state: State, _ detail: String, supportsUpgradeVerification: Bool = true,
                source: String? = nil, reason: String? = nil) {
        self.state = state; self.detail = detail
        self.supportsUpgradeVerification = supportsUpgradeVerification
        self.source = source; self.reason = reason
    }

    /// The "unavailable" packages broken down by feed and cause, largest first, e.g.
    /// `["40 OSV.dev — batch query failed", "12 NVD — no answer (rate-limited or erroring)"]`.
    /// Only NVD is actually rate-limited; the others fail for their own reasons, and saying
    /// "failed or rate-limited" for all of them sent people looking for the wrong fix.
    public static func unavailableBreakdown(_ packages: [Package]) -> [String] {
        var groups: [String: Int] = [:]
        for p in packages {
            guard let c = p.coverage, c.state == .unavailable else { continue }
            let key = (c.source ?? "unknown source") + ": " + (c.reason ?? "lookup failed")
            groups[key, default: 0] += 1
        }
        return groups.sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }
            .map { "\($0.value) \($0.key)" }
    }
}

extension Package {
    var collectorName: String {
        switch ecosystem {
        case .macos: return "macOS"
        case .app: return parent == nil ? "Applications" : "Bundled runtimes"
        case .homebrew, .cask: return "Homebrew"
        case .pypi: return "Python"
        case .npm: return "npm (global)"
        case .crates: return "cargo"
        case .rubygems: return "Ruby gems"
        case .go: return "Go binaries"
        case .browserExtension: return "Browser extensions"
        }
    }
    /// Installation identity survives upgrades, but keeps separate environments distinct.
    public var installationKey: String {
        var path = location
        if ecosystem == .homebrew, Version.stripBrewRevision((path as NSString).lastPathComponent) == version {
            path = (path as NSString).deletingLastPathComponent
        }
        if ecosystem == .browserExtension,
           ((path as NSString).deletingLastPathComponent as NSString).lastPathComponent == bundleID {
            path = (path as NSString).deletingLastPathComponent
        }
        return "\(ecosystem.rawValue)|\(parent ?? "")|\(bundleID ?? name)|\(path)"
    }
}

extension ScanReport {
    public var coverageGaps: [Package] { packages.filter { $0.coverage?.state != .checked } }
    public var coverageWarnings: [SourceStatus] { sources.filter { $0.state == .failed || $0.state == .warning } }
}

public struct FindingException: Codable, Identifiable, Hashable, Sendable {
    public enum Scope: String, Codable, CaseIterable, Sendable { case installation, version, advisory }
    public var id: UUID = UUID()
    public var installation: String
    public var packageName: String
    public var scope: Scope
    public var version: String
    public var advisory: String?
    public var reason: String
    public var expires: Date
    /// Exceptions made before exploitation was known reopen when that changes.
    public var exploitedWhenAccepted: Bool

    public init(package: Package, vulnerability: Vulnerability?, scope: Scope, reason: String,
                expires: Date, exploited: Bool) {
        installation = package.installationKey; packageName = package.displayName
        self.scope = scope; version = package.version
        advisory = vulnerability?.headlineID; self.reason = reason; self.expires = expires
        exploitedWhenAccepted = exploited
    }

    public func applies(to package: Package, vulnerability: Vulnerability, now: Date = Date()) -> Bool {
        guard expires > now, installation == package.installationKey,
              !vulnerability.isKEV || (exploitedWhenAccepted && advisory == vulnerability.headlineID) else { return false }
        switch scope {
        case .installation: return true
        case .version: return version == package.version
        case .advisory: return advisory == vulnerability.headlineID
        }
    }
}

public enum RemediationOutcome: String, Sendable {
    case fixed = "Fixed"
    case removed = "Removed"
    case notChecked = "No longer checked"
    case unavailable = "Lookup unavailable"
    case unconfirmed = "No longer matched; fix unconfirmed"

    public static func assess(_ package: Package, in current: ScanReport, previous: ScanReport) -> Self {
        guard !current.partial else { return .unavailable }
        guard let scope = current.scanOptions, scope == previous.scanOptions else { return .notChecked }
        guard let installed = current.packages.first(where: { $0.installationKey == package.installationKey }) else {
            guard !scope.offline, current.coverageWarnings.isEmpty,
                  current.sources.contains(where: { $0.name == package.collectorName && $0.state == .ok }) else { return .notChecked }
            return .removed
        }
        guard let coverage = installed.coverage else { return .notChecked }
        switch coverage.state {
        case .disabled, .noMapping: return .notChecked
        case .unavailable, .cached, .pending: return .unavailable
        case .checked:
            guard current.coverageWarnings.isEmpty else { return .unavailable }
            // GIT-tag lookups cannot establish whether an upstream tag exists.
            if installed.coverage?.supportsUpgradeVerification != true { return .unconfirmed }
            return Version.less(package.version, installed.version, in: installed.ecosystem) ? .fixed : .unconfirmed
        }
    }
}
