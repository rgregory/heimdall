import Foundation

public struct ScanOptions: Codable, Sendable, Equatable {
    public var apps = true
    public var homebrew = true
    public var useBrewVulns = true
    public var languages = LanguageOptions()
    /// Look installed apps, macOS and Safari up in NVD (rate-limited without an API key).
    public var nvd = true
    public var epss = true
    /// Use cached feeds only; make no network requests.
    public var offline = false
    /// Keep NVD matches whose applicability statement has no version bounds at all.
    public var includeUnbounded = false
    public var extraAppRoots: [String] = []
    /// Apple per-release notes, Chrome Releases, Mozilla MFSA, Microsoft MSRC.
    public var vendorFeeds = true
    /// cvelistV5 + CISA Vulnrichment scores for advisories left unrated.
    public var cveRecords = true
    /// EUVD and VulnCheck exploited lists, Exploit-DB / Metasploit / nuclei.
    public var exploitSignals = true
    /// Sparkle feeds, App Store and the Homebrew cask index.
    public var updateChecks = true
    /// Browser extensions in your profiles, against a malicious-extension list.
    public var extensions = true
    public init() {}

    // Settings saved by older versions lack the newer keys; fill them with defaults.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = ScanOptions()
        apps = try c.decodeIfPresent(Bool.self, forKey: .apps) ?? d.apps
        homebrew = try c.decodeIfPresent(Bool.self, forKey: .homebrew) ?? d.homebrew
        useBrewVulns = try c.decodeIfPresent(Bool.self, forKey: .useBrewVulns) ?? d.useBrewVulns
        languages = try c.decodeIfPresent(LanguageOptions.self, forKey: .languages) ?? d.languages
        nvd = try c.decodeIfPresent(Bool.self, forKey: .nvd) ?? d.nvd
        epss = try c.decodeIfPresent(Bool.self, forKey: .epss) ?? d.epss
        offline = try c.decodeIfPresent(Bool.self, forKey: .offline) ?? d.offline
        includeUnbounded = try c.decodeIfPresent(Bool.self, forKey: .includeUnbounded) ?? d.includeUnbounded
        extraAppRoots = try c.decodeIfPresent([String].self, forKey: .extraAppRoots) ?? d.extraAppRoots
        vendorFeeds = try c.decodeIfPresent(Bool.self, forKey: .vendorFeeds) ?? d.vendorFeeds
        cveRecords = try c.decodeIfPresent(Bool.self, forKey: .cveRecords) ?? d.cveRecords
        exploitSignals = try c.decodeIfPresent(Bool.self, forKey: .exploitSignals) ?? d.exploitSignals
        updateChecks = try c.decodeIfPresent(Bool.self, forKey: .updateChecks) ?? d.updateChecks
        extensions = try c.decodeIfPresent(Bool.self, forKey: .extensions) ?? d.extensions
    }
}

public typealias Progress = @Sendable (_ stage: String, _ fraction: Double) -> Void

/// Runs every collector and matcher as the current user and assembles a report.
public struct Scanner: Sendable {
    public let options: ScanOptions
    public let nvdAPIKey: String?
    public let vulnCheckToken: String?

    public init(options: ScanOptions, nvdAPIKey: String? = nil, vulnCheckToken: String? = nil) {
        self.options = options; self.nvdAPIKey = nvdAPIKey; self.vulnCheckToken = vulnCheckToken
    }

    /// `partial` receives interim reports (fast sources first, then after each NVD product) so a UI
    /// can show results while the rate-limited NVD lookups are still running.
    public func run(progress: @escaping Progress = { _, _ in }, partial: (@Sendable (ScanReport) -> Void)? = nil) async -> ScanReport {
        let started = Date()
        var sources: [SourceStatus] = []
        var packages: [Package] = []

        // ---- Inventory
        progress("Reading the macOS version", 0.01)
        let sys = SystemCollector.collect()
        var posture = sys.posture
        packages += sys.packages; sources.append(sys.status)

        if options.apps {
            progress("Reading application bundles", 0.03)
            let a = AppCollector.collect(extraRoots: options.extraAppRoots)
            packages += a.packages; sources += a.status
        }
        var brewVulns: Data?
        if options.homebrew {
            progress("Asking Homebrew what is installed", 0.06)
            let b = await BrewCollector.collect(useBrewVulns: options.useBrewVulns, offline: options.offline)
            packages += b.packages; sources += b.status; brewVulns = b.brewVulns
        }
        progress("Reading Python, npm, cargo, gem and Go metadata", 0.12)
        let l = LanguageCollector.collect(options.languages)
        packages += l.packages; sources += l.status
        if options.extensions {
            progress("Reading browser extensions", 0.13)
            let e = ExtensionCollector.collect()
            packages += e.packages; sources += e.status
        }
        annotateCasks(&packages)
        if let s = packages.first(where: { $0.bundleID == "com.apple.Safari" }) { posture.safariVersion = s.version }

        // ---- Feeds
        progress("Loading the CISA KEV catalog", 0.16)
        let (kev, kevStatus) = await KEVCatalog.load(offline: options.offline)
        sources.append(kevStatus)
        progress("Loading Apple security releases", 0.19)
        let (apple, appleStatus) = await AppleReleases.load(offline: options.offline)
        sources.append(appleStatus)

        var vulns: [String: [Vulnerability]] = [:]   // package id → vulns
        func add(_ id: String, _ v: [Vulnerability]) { if !v.isEmpty { vulns[id, default: []] += v } }

        // ---- Homebrew's own advisories, if this Homebrew has `brew vulns`
        var osvPackages = packages.filter { $0.ecosystem.osvName != nil }
        if let brewVulns {
            let byName = BrewVulnsParser.parse(brewVulns)
            for p in packages where p.ecosystem == .homebrew { add(p.id, byName[p.name] ?? []) }
        } else {
            osvPackages += packages.filter { $0.ecosystem == .homebrew && $0.repo != nil }
        }

        // ---- OSV
        progress("Checking \(osvPackages.count) packages against OSV.dev", 0.24)
        let (osv, osvStatus) = await OSVClient.match(osvPackages, offline: options.offline)
        for (k, v) in osv { add(k, v) }
        sources.append(osvStatus)

        // ---- macOS & Safari releases
        if !posture.osVersion.isEmpty, !apple.isEmpty {
            let b = AppleReleases.behind(apple, product: "macOS", installed: posture.osVersion)
            posture.latestInLine = b.latest; posture.releasesBehind = b.newer
        }
        if let sv = posture.safariVersion, !apple.isEmpty {
            posture.safariLatest = AppleReleases.behind(apple, product: "Safari", installed: sv).latest
        }

        // ---- Malicious browser extensions
        if options.extensions, packages.contains(where: { $0.ecosystem == .browserExtension }) {
            let (bad, st) = await MaliciousExtensions.load(offline: options.offline)
            sources.append(st)
            for p in packages where p.ecosystem == .browserExtension {
                guard let id = p.bundleID, bad.contains(id) else { continue }
                var v = Vulnerability(id: "Malicious extension \(id)")
                v.summary = "\(p.name) is on a list of Chrome Web Store extensions removed for malware. Remove it and review what it could access."
                v.severity = .critical
                v.source = "Malicious extension list"
                v.references = ["https://chromewebstore.google.com/detail/\(id)", MaliciousExtensions.url]
                v.kev = KEVEntry(cveID: v.id, vendorProject: p.browser ?? "", product: p.name, vulnerabilityName: "Known malicious browser extension",
                                 dateAdded: "", shortDescription: v.summary, requiredAction: "Remove the extension.", dueDate: "", knownRansomwareCampaignUse: "", source: "Malicious extension list")
                add(p.id, [v])
            }
        }

        // ---- Vendor advisories (exact fixed versions from Apple, Google, Mozilla, Microsoft)
        if options.vendorFeeds {
            progress("Reading Apple's notes for the releases you're missing", 0.27)
            if let mac = packages.first(where: { $0.ecosystem == .macos }), !posture.releasesBehind.isEmpty {
                add(mac.id, await AppleNotes.open(in: posture.releasesBehind, offline: options.offline))
            }
            if let saf = packages.first(where: { $0.bundleID == "com.apple.Safari" }) {
                let newer = AppleReleases.behind(apple, product: "Safari", installed: saf.version).newer
                if !newer.isEmpty { add(saf.id, await AppleNotes.open(in: newer, offline: options.offline)) }
            }
            sources.append(SourceStatus(name: "Apple security notes", state: .ok, detail: posture.releasesBehind.isEmpty ? "macOS is current; nothing to read" : "CVE lists from \(posture.releasesBehind.count) missing releases", updated: Date()))

            if let chrome = packages.first(where: { $0.bundleID == "com.google.Chrome" }) {
                progress("Reading Chrome Releases", 0.28)
                let (posts, st) = await ChromeReleases.load(offline: options.offline)
                sources.append(st)
                add(chrome.id, ChromeReleases.open(posts, installed: chrome.version))
            }
            for (bid, product) in [("org.mozilla.firefox", "firefox"), ("org.mozilla.firefoxdeveloperedition", "firefox"), ("org.mozilla.thunderbird", "thunderbird")] {
                guard let p = packages.first(where: { $0.bundleID == bid }) else { continue }
                progress("Reading Mozilla advisories for \(p.name)", 0.29)
                let v = await MozillaAdvisories.open(product: product, installed: p.version, offline: options.offline)
                add(p.id, v)
                sources.append(SourceStatus(name: "Mozilla MFSA (\(p.name))", state: .ok, detail: "\(v.count) advisories fixed after \(p.version)", count: v.count, updated: Date()))
            }
            let ms = packages.filter { $0.ecosystem == .app && MSRC.isMicrosoft($0) }
            if !ms.isEmpty {
                progress("Reading Microsoft's monthly security releases", 0.30)
                let since = ms.compactMap(\.modified).min() ?? Date().addingTimeInterval(-90 * 86400)
                let (entries, st) = await MSRC.load(since: since, offline: options.offline)
                sources.append(st)
                for p in ms { add(p.id, MSRC.open(entries, for: p)) }
            }
        }
        if options.updateChecks {
            progress("Checking for newer app versions", 0.31)
            sources.append(await UpdateChecks.apply(&packages, offline: options.offline))
        }

        func interim() {
            guard let partial else { return }
            var r = Self.assemble(packages: packages, vulns: vulns, posture: posture, sources: sources, kev: kev)
            r.duration = Date().timeIntervalSince(started)
            r.partial = true
            partial(r)
        }
        interim()

        // ---- NVD: apps, macOS, Safari
        if options.nvd {
            let nvd = NVDClient(apiKey: nvdAPIKey, offline: options.offline)
            let catalog = AppCatalog.load()
            var targets: [(Package, AppCPE)] = []
            if let mac = packages.first(where: { $0.ecosystem == .macos }) {
                targets.append((mac, AppCPE(bundleID: "macos", cpe: ["o:apple:macos"], kevVendor: "^apple$", kevProduct: "macos|multiple products|webkit|kernel")))
            }
            for p in packages where p.ecosystem == .app && !p.version.isEmpty && !AppCollector.isApple(p) {
                if let e = AppCatalog.entry(for: p, in: catalog) { targets.append((p, e)) }
            }
            var unbounded = 0, failed: [String] = []
            for (i, (p, entry)) in targets.enumerated() {
                progress("NVD: \(p.name) \(p.version)\(nvdAPIKey == nil ? " (rate-limited without an API key)" : "")", 0.32 + 0.58 * Double(i) / Double(max(targets.count, 1)))
                let r = await nvdMatch(p, entry, nvd: nvd, kev: kev, posture: posture)
                add(p.id, r.vulns); unbounded += r.unbounded
                if r.failed { failed.append(p.name) }
                if !r.vulns.isEmpty { interim() }
            }
            let reqs = await nvd.requests
            let detail = "\(targets.count) products checked, \(reqs) requests" + (nvdAPIKey == nil ? " (no API key: ~6 s apart)" : "")
                + (unbounded > 0 && !options.includeUnbounded ? "; \(unbounded) matches without version bounds ignored" : "")
                + (failed.isEmpty ? "" : "; no answer for \(failed.joined(separator: ", "))")
            sources.append(SourceStatus(name: "NVD", state: failed.isEmpty ? .ok : .warning, detail: detail, count: targets.count, updated: Date()))
        } else {
            sources.append(SourceStatus(name: "NVD", state: .skipped, detail: "turned off in Settings — apps, macOS and Safari are not checked"))
        }

        // ---- KEV tagging and EPSS
        progress("Flagging known-exploited vulnerabilities", 0.92)
        for (k, list) in vulns {
            vulns[k] = list.map { v in
                var v = v
                if v.kev == nil { v.kev = kev.first(of: v.cves) }
                return v
            }
        }
        // ---- More exploited-in-the-wild signals, public exploits, CVE-program scores
        if options.exploitSignals {
            progress("Checking EUVD, VulnCheck and public-exploit indexes", 0.93)
            let (euvd, s1) = await EUVDExploited.load(offline: options.offline)
            let (vc, s2) = await VulnCheckKEV.load(token: vulnCheckToken, offline: options.offline)
            let (exploits, s3) = await ExploitIndex.load(offline: options.offline)
            sources += [s1, s2, s3]
            for (k, list) in vulns {
                vulns[k] = list.map { v in
                    var v = v
                    if v.kev == nil { v.kev = kev.first(of: v.cves) ?? v.cves.lazy.compactMap { vc.entries[$0] ?? euvd.entries[$0] }.first }
                    let ex = v.cves.flatMap { exploits[$0] ?? [] }.uniqued()
                    if !ex.isEmpty { v.publicExploits = ex }
                    return v
                }
            }
        }
        if options.cveRecords {
            let unrated = vulns.values.flatMap { $0 }.filter { $0.cvss == nil }.flatMap(\.cves)
            if !unrated.isEmpty {
                progress("Scoring \(min(unrated.count, 300)) unrated advisories from CVE records", 0.94)
                let info = await CVERecords.enrich(unrated, offline: options.offline)
                var filled = 0
                for (k, list) in vulns {
                    vulns[k] = list.map { v in
                        var v = v
                        guard let i = v.cves.compactMap({ info[$0] }).first else { return v }
                        if v.cvss == nil, let c = i.cvss { v.cvss = c; v.vector = v.vector ?? i.vector; v.severity = Severity(score: c); filled += 1 }
                        if v.summary.isEmpty, let t = i.title { v.summary = t }
                        if v.kev == nil, i.exploitation == "active" {
                            v.kev = KEVEntry(cveID: v.headlineID, vendorProject: "", product: "", vulnerabilityName: "CISA SSVC: exploitation active",
                                             dateAdded: "", shortDescription: "CISA's Vulnrichment assessment says this is being exploited.", requiredAction: "",
                                             dueDate: "", knownRansomwareCampaignUse: "", source: "CISA SSVC")
                        }
                        return v
                    }
                }
                sources.append(SourceStatus(name: "CVE records", state: .ok, detail: "cvelistV5 + CISA Vulnrichment: scored \(filled) advisories NVD/OSV left unrated", count: filled, updated: Date()))
            }
        }

        if options.epss {
            progress("Fetching EPSS exploit-probability scores", 0.95)
            let cves = vulns.values.flatMap { $0.flatMap(\.cves) }.uniqued()
            let (scores, st) = await EPSS.scores(for: cves, offline: options.offline)
            sources.append(st)
            for (k, list) in vulns {
                vulns[k] = list.map { v in
                    var v = v
                    if let s = v.cves.compactMap({ scores[$0] }).max(by: { $0.0 < $1.0 }) { v.epss = s.0; v.epssPercentile = s.1 }
                    return v
                }
            }
        }

        progress("Done", 1)
        var report = Self.assemble(packages: packages, vulns: vulns, posture: posture, sources: sources, kev: kev)
        report.duration = Date().timeIntervalSince(started)
        return report
    }

    static func assemble(packages: [Package], vulns: [String: [Vulnerability]], posture: SystemPosture, sources: [SourceStatus], kev: KEVCatalog) -> ScanReport {
        let byID = Dictionary(packages.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        var findings: [Finding] = []
        for (id, list) in vulns {
            guard let p = byID[id] else { continue }
            let tagged = list.map { v -> Vulnerability in var v = v; if v.kev == nil { v.kev = kev.first(of: v.cves) }; return v }
            let merged = dedupe(tagged).sorted { $0.priority > $1.priority }
            var f = Finding(package: p, vulns: merged, fixHint: fixHint(p, merged))
            if awaitingRelease(p, merged) { f.awaitingRelease = true }
            findings.append(f)
        }
        findings.sort { $0.priority > $1.priority }
        let sorted = packages.sorted { ($0.ecosystem, $0.name.lowercased()) < ($1.ecosystem, $1.name.lowercased()) }
        var r = ScanReport(generated: Date(), posture: posture, packages: sorted, findings: findings, sources: sources)
        r.kevCatalogVersion = kev.version
        r.timeline = Timeline.build(kev: kev, packages: packages, findings: findings)
        return r
    }

    // MARK: NVD matching for one app / OS

    func nvdMatch(_ p: Package, _ entry: AppCPE, nvd: NVDClient, kev: KEVCatalog, posture: SystemPosture) async -> (vulns: [Vulnerability], unbounded: Int, failed: Bool) {
        var out: [String: Vulnerability] = [:]
        var analyzedKEV = Set<String>()     // KEV CVEs NVD has an applicability statement for under this CPE
        var unbounded = 0, answered = false
        for cpe in entry.cpe {
            let f = cpe.split(separator: ":").map(String.init)
            let (part, vendor, product) = f.count == 3 ? (f[0], f[1], f[2]) : ("a", f[0], f.count > 1 ? f[1] : "")
            if let list = await nvd.cves(part: part, vendor: vendor, product: product, version: p.version) {
                answered = true
                for c in list {
                    switch NVDClient.evaluate(c, part: part, vendor: vendor, product: product, version: p.version) {
                    case .affected: out[c.id] = out[c.id] ?? NVDClient.vulnerability(c)
                    case .affectedUnbounded:
                        unbounded += 1
                        if options.includeUnbounded { out[c.id] = out[c.id] ?? NVDClient.vulnerability(c, confidence: .heuristic) }
                    case .notAffected: break
                    }
                    if let k = c.kevAdded, out[c.id] != nil, out[c.id]?.kev == nil {
                        out[c.id]?.kev = kev[c.id] ?? KEVEntry(cveID: c.id, vendorProject: vendor, product: product, vulnerabilityName: "", dateAdded: k,
                                                                shortDescription: "", requiredAction: "", dueDate: "", knownRansomwareCampaignUse: "")
                    }
                }
            }
            if let k = await nvd.cves(part: part, vendor: vendor, product: product, version: nil) {
                for c in k where !c.configs.isEmpty { analyzedKEV.insert(c.id) }
            }
        }

        // KEV entries NVD hasn't analysed for this product (new, or Chromium bugs in a Chromium-based
        // browser): flag them when the app on disk is older than the KEV listing.
        if let kv = entry.kevVendor, let kp = entry.kevProduct {
            let cutoff = Date().addingTimeInterval(-730 * 86400)
            var since: Date? = p.modified
            if p.ecosystem == .macos {
                // For macOS, "older than the listing" means: a newer security release has shipped since.
                since = posture.releasesBehind.first.map { $0.date.addingTimeInterval(-3 * 86400) }
            }
            if let since {
                for k in kev.entries.values where k.vendorProject.range(of: kv, options: [.regularExpression, .caseInsensitive]) != nil
                    && k.product.range(of: kp, options: [.regularExpression, .caseInsensitive]) != nil {
                    guard out[k.cveID] == nil, !analyzedKEV.contains(k.cveID),
                          let added = parseDate(k.dateAdded), added > cutoff, added > since else { continue }
                    var v = Vulnerability(id: k.cveID)
                    v.summary = k.shortDescription.isEmpty ? k.vulnerabilityName : k.shortDescription
                    v.kev = k
                    v.severity = .high
                    v.published = added
                    v.source = p.ecosystem == .macos ? "Apple releases + KEV" : "KEV (date heuristic)"
                    v.confidence = .heuristic
                    out[k.cveID] = v
                }
            }
        }
        return (Array(out.values), unbounded, !answered && !options.offline)
    }

    // MARK: helpers

    func annotateCasks(_ packages: inout [Package]) {
        var appToCask: [String: String] = [:]
        for c in packages where c.ecosystem == .cask {
            for n in (c.bundleID ?? "").split(separator: "|") { appToCask[String(n)] = c.name }
        }
        for i in packages.indices where packages[i].ecosystem == .app {
            let file = (packages[i].location as NSString).lastPathComponent
            if let t = appToCask[file] { packages[i].cask = t }
        }
    }

    /// One row per CVE: GHSA, PYSEC and OSV ids for the same CVE are merged.
    static func dedupe(_ list: [Vulnerability]) -> [Vulnerability] {
        var groups: [String: Vulnerability] = [:]
        var order: [String] = []
        for v in list {
            let key = v.headlineID
            if var g = groups[key] {
                g.aliases = (g.aliases + [v.id] + v.aliases).uniqued().filter { $0 != g.id }
                g.fixed = (g.fixed + v.fixed).uniqued().sorted { Version.less($0, $1) }
                if g.cvss == nil, let c = v.cvss { g.cvss = c; g.vector = v.vector }
                if v.severity > g.severity { g.severity = v.severity }
                if g.summary.isEmpty { g.summary = v.summary }
                if g.kev == nil { g.kev = v.kev }
                if v.confidence == .versionMatch { g.confidence = .versionMatch }
                g.references = (g.references + v.references).uniqued()
                groups[key] = g
            } else { groups[key] = v; order.append(key) }
        }
        return order.compactMap { groups[$0] }
    }

    static func isFixVersion(_ value: String) -> Bool {
        value.range(of: #"\A[0-9][0-9A-Za-z.!+_~:-]*\z"#, options: .regularExpression) != nil
    }

    static func isPackageName(_ value: String) -> Bool {
        value.range(of: #"\A(?:[A-Za-z0-9][A-Za-z0-9._+-]*(?:/[A-Za-z0-9][A-Za-z0-9._+-]*)*|@[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*)\z"#, options: .regularExpression) != nil
    }

    /// Nothing to upgrade to: no advisory names a released version above what's installed, and
    /// (for Homebrew, which knows) the installed version is already the newest. Typical for
    /// OSS-Fuzz reports fixed by a commit that hasn't shipped yet.
    public static func awaitingRelease(_ p: Package, _ vulns: [Vulnerability]) -> Bool {
        let released = vulns.contains { v in v.fixed.contains { Self.isFixVersion($0) && Version.compare($0, p.version) > 0 } }
        guard !released else { return false }
        switch p.ecosystem {
        case .homebrew, .cask: return !p.outdated
        case .pypi, .npm, .crates, .rubygems, .go:
            // Without a "latest" for these, only say so when advisories carry fix info at all.
            return vulns.allSatisfy { v in v.fixed.allSatisfy { $0.hasPrefix("commit") || Version.compare($0, p.version) <= 0 } }
                && vulns.contains { !$0.fixed.isEmpty }
        default: return false
        }
    }

    public static func fixHint(_ p: Package, _ vulns: [Vulnerability]) -> String {
        // Per advisory, the first fixed release above what's installed; then the highest of those.
        let firsts = vulns.compactMap { v in
            v.fixed.filter { Self.isFixVersion($0) && Version.compare($0, p.version) > 0 }.min(by: { Version.less($0, $1) })
        }
        let target = firsts.max(by: { Version.less($0, $1) })
        // Names are metadata too. Reject option-like names and non-package syntax before
        // offering a command, then quote every argument independently of validation.
        let names = p.ecosystem == .app ? [p.cask].compactMap { $0 } : [p.name, p.parent, p.cask].compactMap { $0 }
        if [.homebrew, .cask, .pypi, .npm, .crates, .rubygems].contains(p.ecosystem) || p.cask != nil {
            guard names.allSatisfy(Self.isPackageName) else { return "Update this package using its package manager; its metadata contains an invalid package name." }
        }
        let to = target.map { " (fixed in \($0) or later)" } ?? ""
        if awaitingRelease(p, vulns) {
            let commit = vulns.flatMap(\.fixed).first { $0.hasPrefix("commit") }
            return "No fixed release yet — \(p.name) \(p.version) is the newest available. "
                + (commit.map { "Fixed upstream (\($0)); it arrives with the next release." } ?? "Watch for an update.")
        }
        switch p.ecosystem {
        case .macos: return "System Settings → General → Software Update"
        case .homebrew: return "brew upgrade \(Shell.quote(p.name))"
        case .cask: return "brew upgrade --cask \(Shell.quote(p.name))"
        case .app:
            if let c = p.cask { return "brew upgrade --cask \(Shell.quote(c))" }
            if p.appStore { return "Update \(p.name) from the App Store" }
            if MSRC.isMicrosoft(p) && p.bundleID != "com.microsoft.VSCode" { return "Help → Check for Updates (Microsoft AutoUpdate)\(target.map { " — needs build \($0)" } ?? "")" }
            return "Update \(p.name) from its menu (Check for Updates…)"
        case .pypi:
            if let parent = p.parent {
                if p.source.hasPrefix("pipx") { return "pipx upgrade \(Shell.quote(parent))  — or: pipx runpip \(Shell.quote(parent)) install -U \(Shell.quote(p.name))" }
                if p.source.hasPrefix("uv tool") { return "uv tool upgrade \(Shell.quote(parent))" }
                if p.source.contains("Homebrew formula") { return "brew upgrade \(Shell.quote(parent))" }
            }
            return "python3 -m pip install -U \(Shell.quote(p.name + (target.map { ">=\($0)" } ?? "")))  — in \(p.location)"
        case .npm:
            if let parent = p.parent { return "npm update -g \(Shell.quote(parent))  — \(p.name) is a dependency\(to)" }
            return "npm install -g \(Shell.quote(p.name + "@latest"))"
        case .crates: return "cargo install \(Shell.quote(p.name)) --locked --force"
        case .rubygems: return "gem update \(Shell.quote(p.name))"
        case .browserExtension: return "Remove it: \(p.browser ?? "the browser") → Extensions → \(p.name) → Remove"
        case .go:
            let bin = p.parent ?? "the binary"
            if p.name == "stdlib" { return "Rebuild or upgrade \(bin) with a newer Go toolchain\(to)" }
            return "Upgrade \(bin) (it embeds \(p.name)\(to))"
        }
    }
}
