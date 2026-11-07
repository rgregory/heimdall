import Foundation

/// A year of CISA KEV listings, each marked by how it relates to this Mac.
public struct TimelineEntry: Codable, Hashable, Identifiable, Sendable {
    public enum Relevance: String, Codable, Sendable {
        /// A vulnerable version is installed right now.
        case affected
        /// The product is installed, but no vulnerable version was found.
        case installed
        /// Not on this Mac.
        case elsewhere
    }
    public var cve: String
    public var added: String          // yyyy-MM-dd
    public var vendor: String
    public var product: String
    public var name: String
    public var summary: String
    public var ransomware: Bool
    public var relevance: Relevance
    /// The installed package(s) it relates to, "Google Chrome 142.0.7444.60".
    public var packages: [String] = []
    /// Package ids (for jumping to the finding when affected).
    public var packageIDs: [String] = []
    public var fix: String? = nil
    public var id: String { cve }
    public var date: Date? { parseDate(added) }
}

public enum Timeline {
    public static func build(kev: KEVCatalog, packages: [Package], findings: [Finding], days: Int = 365) -> [TimelineEntry] {
        let cutoff = Date().addingTimeInterval(-Double(days) * 86400)
        let catalog = AppCatalog.load()
        // CVE → findings that carry it (vulnerable here, now).
        var open: [String: [Finding]] = [:]
        for f in findings { for v in f.vulns { for c in v.cves { open[c, default: []].append(f) } } }

        var out: [TimelineEntry] = []
        for k in kev.entries.values {
            guard let d = parseDate(k.dateAdded), d >= cutoff else { continue }
            var e = TimelineEntry(cve: k.cveID, added: k.dateAdded, vendor: k.vendorProject, product: k.product, name: k.vulnerabilityName,
                                  summary: k.shortDescription, ransomware: k.ransomware, relevance: .elsewhere)
            if let fs = open[k.cveID], !fs.isEmpty {
                e.relevance = .affected
                e.packages = fs.map { "\($0.package.displayName) \($0.package.version)" }.uniqued()
                e.packageIDs = fs.map(\.package.id).uniqued()
                e.fix = fs.first?.fixHint
            } else {
                let related = relatedPackages(k, packages, catalog)
                if !related.isEmpty {
                    e.relevance = .installed
                    e.packages = related.map { "\($0.displayName) \($0.version)" }.uniqued()
                    e.packageIDs = related.map(\.id)
                }
            }
            out.append(e)
        }
        return out.sorted { ($0.added, $0.cve) > ($1.added, $1.cve) }
    }

    /// Installed software a KEV row is about, by vendor/product rules and by name.
    static func relatedPackages(_ k: KEVEntry, _ packages: [Package], _ catalog: [AppCPE]) -> [Package] {
        let vendor = k.vendorProject, product = k.product
        func rx(_ s: String, _ p: String) -> Bool { s.range(of: p, options: [.regularExpression, .caseInsensitive]) != nil }
        var out: [Package] = []
        for p in packages {
            switch p.ecosystem {
            case .macos:
                if rx(vendor, "^apple$") && rx(product, "macos|multiple products|webkit|kernel") { out.append(p) }
            case .app:
                if p.bundleID == "com.apple.Safari", rx(vendor, "^apple$"), rx(product, "safari|webkit|multiple products") { out.append(p); continue }
                if let e = AppCatalog.entry(for: p, in: catalog), let kv = e.kevVendor, let kp = e.kevProduct, rx(vendor, kv), rx(product, kp) { out.append(p); continue }
                if MSRC.isMicrosoft(p), rx(vendor, "^microsoft$"), rx(product, "office|word|excel|powerpoint|outlook|teams|edge|visual studio code") { out.append(p); continue }
                if nameMatch(p.name, product) { out.append(p) }
            case .homebrew, .cask, .pypi, .npm, .rubygems, .crates:
                if p.parent == nil, nameMatch(p.name, product) || nameMatch(p.name, vendor + " " + product) { out.append(p) }
            case .go, .browserExtension:
                break
            }
        }
        return out
    }

    static let generic: Set<String> = ["server", "client", "core", "server", "manager", "service", "agent", "suite", "edition",
                                       "community", "enterprise", "software", "multiple", "products", "system", "web", "http", "open",
                                       "apple", "microsoft", "google", "linux", "windows", "kernel", "framework", "library"]

    /// "openssh" ~ "OpenSSH", "php" ~ "PHP", "next" ~ "Next.js" — whole tokens only, no generic words.
    static func nameMatch(_ pkg: String, _ product: String) -> Bool {
        let n = pkg.lowercased().replacingOccurrences(of: #"[@].*$"#, with: "", options: .regularExpression)   // php@8.3 → php
            .filter { $0.isLetter || $0.isNumber }
        guard n.count >= 3, !generic.contains(n) else { return false }
        let tokens = product.lowercased().split(whereSeparator: { !($0.isLetter || $0.isNumber) }).map(String.init)
        let joined = tokens.joined()
        return tokens.contains(n) || joined == n
    }
}
