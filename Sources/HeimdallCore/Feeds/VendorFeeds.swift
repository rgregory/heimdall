import Foundation

// Vendor advisory feeds: exact "fixed in" versions straight from the vendor, usually days
// ahead of NVD's analysis.

// MARK: - Apple per-release security notes

public enum AppleNotes {
    /// CVEs fixed in each release newer than what's installed — so still open here.
    public static func open(in releases: [AppleRelease], offline: Bool) async -> [Vulnerability] {
        let cache = DiskCache("apple-notes")
        let pages: [(AppleRelease, String?)] = await concurrentMap(Array(releases.filter(\.hasCVEs).prefix(12)), width: 4) { rel in
            let key = "note-" + stableHash(rel.link) + ".html"
            if let d = cache.data(key, maxAge: offline ? nil : 30 * 86400) { return (rel, String(decoding: d, as: UTF8.self)) }
            if offline { return (rel, nil) }
            guard let d = try? await HTTP.get(rel.link, headers: ["Accept-Language": "en-US"]) else { return (rel, nil) }
            cache.store(key, d)
            return (rel, String(decoding: d, as: UTF8.self))
        }
        var out: [String: Vulnerability] = [:]
        for (rel, html) in pages {
            guard let html else { continue }
            for e in parse(html) {
                var v = out[e.cve] ?? Vulnerability(id: e.cve)
                v.summary = v.summary.isEmpty ? "\(e.component): \(e.impact)" : v.summary
                v.fixed = (v.fixed + [rel.version]).uniqued().sorted { Version.less($0, $1) }
                v.published = v.published ?? rel.date
                v.references = (v.references + [rel.link]).uniqued()
                v.source = "Apple security notes"
                out[e.cve] = v
            }
        }
        return Array(out.values)
    }

    struct Entry { var component: String; var impact: String; var cve: String }

    static func parse(_ html: String) -> [Entry] {
        var out: [Entry] = []
        let blocks = html.components(separatedBy: "<h3")
        for b in blocks.dropFirst() {
            let comp = AppleReleases.decode(b.firstMatch(#"^[^>]*>([\s\S]*?)</h3>"#)?[1] ?? "")
            let impact = AppleReleases.decode(b.firstMatch(#"Impact:\s*([\s\S]*?)</p>"#)?[1] ?? "")
            for c in Set(b.allMatches(#"CVE-\d{4}-\d{4,}"#).map { $0[0] }) {
                out.append(Entry(component: comp, impact: impact, cve: c))
            }
        }
        return out
    }
}

// MARK: - Chrome Releases (stable channel)

public enum ChromeReleases {
    static let feed = "https://chromereleases.googleblog.com/feeds/posts/default?max-results=25&start-index="

    public struct Post: Codable { var version: String; var date: Date?; var link: String; var cves: [Item] }
    public struct Item: Codable { var cve: String; var severity: String; var title: String }

    public static func load(offline: Bool) async -> ([Post], SourceStatus) {
        let cache = DiskCache("feeds")
        var data = cache.data("chrome-releases.xml", maxAge: offline ? nil : 12 * 3600)
        if data == nil && !offline {
            // Blogger serves 25 posts a page; eight pages reach back several months of stable releases.
            var all = Data()
            for start in stride(from: 1, through: 176, by: 25) {
                guard let d = try? await HTTP.get(feed + String(start)) else { break }
                all.append(d)
                if !String(decoding: d, as: UTF8.self).contains("<entry>") { break }
            }
            if !all.isEmpty { data = all; cache.store("chrome-releases.xml", all) } else { data = cache.data("chrome-releases.xml") }
        }
        let posts = data.map { parse(String(decoding: $0, as: UTF8.self)) } ?? []
        return (posts, SourceStatus(name: "Chrome Releases", state: posts.isEmpty ? .warning : .ok,
                                    detail: posts.isEmpty ? "feed unavailable" : "\(posts.count) stable-channel desktop updates", count: posts.count, updated: Date()))
    }

    static func parse(_ xml: String) -> [Post] {
        var out: [Post] = []
        for e in xml.allMatches(#"<entry>([\s\S]*?)</entry>"#) {
            let entry = e[1]
            guard let title = entry.firstMatch(#"<title[^>]*>([\s\S]*?)</title>"#)?[1], title.contains("Stable Channel Update for Desktop") else { continue }
            let raw = entry.firstMatch(#"<content[^>]*>([\s\S]*?)</content>"#)?[1] ?? ""
            let text = AppleReleases.decode(raw.replacingOccurrences(of: "&lt;", with: "<").replacingOccurrences(of: "&gt;", with: ">")
                .replacingOccurrences(of: "&amp;", with: "&").replacingOccurrences(of: "&quot;", with: "\""))
            guard let ver = text.firstMatch(#"(\d+\.\d+\.\d+\.\d+)(?:/\.?\d+)*\s*(?:for\s+)?(?:Windows|Mac)"#)?[1] else { continue }
            var items: [Item] = []
            for m in text.allMatches(#"(Critical|High|Medium|Low)\s+(CVE-\d{4}-\d{4,}):\s*([^\[\.]{3,140})"#) {
                items.append(Item(cve: m[2], severity: m[1], title: m[3].trimmed))
            }
            let link = entry.firstMatch(#"<link rel=['"]alternate['"][^>]*href=['"]([^'"]+)"#)?[1] ?? "https://chromereleases.googleblog.com/"
            out.append(Post(version: ver, date: parseDate(entry.firstMatch(#"<published>([^<]+)</published>"#)?[1]), link: link, cves: items))
        }
        return out
    }

    /// Advisories fixed in Chrome releases newer than `installed`.
    public static func open(_ posts: [Post], installed: String) -> [Vulnerability] {
        var out: [String: Vulnerability] = [:]
        for p in posts where Version.compare(p.version, installed) > 0 {
            for i in p.cves {
                var v = out[i.cve] ?? Vulnerability(id: i.cve)
                v.summary = i.title
                v.severity = Severity(label: i.severity)
                v.fixed = (v.fixed + [p.version]).uniqued().sorted { Version.less($0, $1) }
                v.published = v.published ?? p.date
                v.references = [p.link]
                v.source = "Chrome Releases"
                out[i.cve] = v
            }
        }
        return Array(out.values)
    }
}

// MARK: - Mozilla Foundation Security Advisories

public enum MozillaAdvisories {
    /// product: "firefox", "firefox-esr" or "thunderbird"
    public static func open(product: String, installed: String, offline: Bool) async -> [Vulnerability] {
        let cache = DiskCache("mozilla")
        let listURL = "https://www.mozilla.org/en-US/security/known-vulnerabilities/\(product)/"
        var list = cache.data("list-\(product).html", maxAge: offline ? nil : 12 * 3600)
        if list == nil && !offline {
            list = try? await HTTP.get(listURL)
            if let list { cache.store("list-\(product).html", list) } else { list = cache.data("list-\(product).html") }
        }
        guard let list else { return [] }
        let html = String(decoding: list, as: UTF8.self)
        // An ESR install sits several majors behind the release list: use the ESR list instead.
        if product == "firefox" {
            let majors = html.allMatches(#"Fixed in Firefox (\d+)"#).compactMap { Int($0[1]) }
            if let top = majors.max(), let mine = Int(installed.split(separator: ".").first ?? ""), top - mine >= 4 {
                return await open(product: "firefox-esr", installed: installed, offline: offline)
            }
        }
        // Each "Fixed in <Product> <version>" heading is followed by its advisory links.
        var advisories: [(String, String)] = []   // (fixed version, advisory path)
        let parts = html.components(separatedBy: "class=\"level-heading\"")
        for part in parts.dropFirst() {
            guard let ver = part.firstMatch(#"Fixed in [A-Za-z ]+?(\d+(?:\.\d+)*)"#)?[1], Version.compare(ver, installed) > 0 else { continue }
            for m in part.allMatches(#"href="(/en-US/security/advisories/mfsa\d{4}-\d+/)""#) { advisories.append((ver, m[1])) }
        }
        let wanted = Array(advisories.prefix(40))
        let pages: [(String, String, String?)] = await concurrentMap(wanted, width: 4) { a in
            let key = "adv-" + a.1.replacingOccurrences(of: "/", with: "_") + ".html"
            if let d = cache.data(key, maxAge: offline ? nil : 30 * 86400) { return (a.0, a.1, String(decoding: d, as: UTF8.self)) }
            if offline { return (a.0, a.1, nil) }
            guard let d = try? await HTTP.get("https://www.mozilla.org" + a.1) else { return (a.0, a.1, nil) }
            cache.store(key, d)
            return (a.0, a.1, String(decoding: d, as: UTF8.self))
        }
        var out: [String: Vulnerability] = [:]
        for (ver, path, page) in pages {
            guard let page else { continue }
            for sec in page.components(separatedBy: "<section class=\"cve\"").dropFirst() {
                guard let cve = sec.firstMatch(#"(CVE-\d{4}-\d{4,})"#)?[1] else { continue }
                let title = AppleReleases.decode(sec.firstMatch(#"CVE-\d{4}-\d{4,}:\s*([\s\S]*?)</a>"#)?[1] ?? "")
                let impact = sec.firstMatch(#"class="level (critical|high|moderate|low)""#)?[1] ?? ""
                var v = out[cve] ?? Vulnerability(id: cve)
                v.summary = title
                v.severity = Severity(label: impact)
                v.fixed = (v.fixed + [ver]).uniqued().sorted { Version.less($0, $1) }
                v.references = ["https://www.mozilla.org" + path]
                v.source = "Mozilla MFSA"
                out[cve] = v
            }
        }
        return Array(out.values)
    }
}

// MARK: - Microsoft Security Response Center

public enum MSRC {
    public struct Entry: Codable { var cve: String; var title: String; var products: [String]; var fixed: [String]; var exploited: Bool; var cvss: Double?; var month: String }

    /// Which MSRC product names describe an installed app.
    static func products(for bundleID: String) -> (match: (String) -> Bool, titleHint: String?)? {
        let office: (String) -> Bool = { $0.contains("Office") && $0.contains("Mac") }
        switch bundleID {
        case "com.microsoft.Word": return (office, "Word")
        case "com.microsoft.Excel": return (office, "Excel")
        case "com.microsoft.Powerpoint": return (office, "PowerPoint")
        case "com.microsoft.Outlook": return (office, "Outlook")
        case "com.microsoft.onenote.mac": return (office, "OneNote")
        case "com.microsoft.teams2", "com.microsoft.teams": return ({ $0.contains("Teams") && $0.contains("Mac") }, nil)
        case "com.microsoft.edgemac": return ({ $0.hasPrefix("Microsoft Edge") }, nil)
        case "com.microsoft.VSCode": return ({ $0 == "Visual Studio Code" }, nil)
        default: return nil
        }
    }

    public static func isMicrosoft(_ p: Package) -> Bool { p.bundleID.map { products(for: $0) != nil } ?? false }

    /// Monthly CVRF documents back to `since` (at most 12), reduced to Mac-relevant entries.
    public static func load(since: Date, offline: Bool) async -> ([Entry], SourceStatus) {
        let cache = DiskCache("msrc")
        var months: [(String, Date)] = []
        var index = cache.data("updates.json", maxAge: offline ? nil : 86400)
        if index == nil && !offline {
            index = try? await HTTP.get("https://api.msrc.microsoft.com/cvrf/v3.0/updates", headers: ["Accept": "application/json"])
            if let index { cache.store("updates.json", index) } else { index = cache.data("updates.json") }
        }
        if let d = index {
            for v in (jsonObject(d) as? [String: Any])?["value"] as? [[String: Any]] ?? [] {
                if let id = v["ID"] as? String, let date = parseDate(v["InitialReleaseDate"] as? String) { months.append((id, date)) }
            }
        }
        let cutoff = since.addingTimeInterval(-35 * 86400)
        let wanted = months.filter { $0.1 >= cutoff }.sorted { $0.1 > $1.1 }.prefix(12)
        var all: [Entry] = []
        var failed = 0
        for (id, date) in wanted {
            let fresh: TimeInterval = Date().timeIntervalSince(date) < 45 * 86400 ? 86400 : 30 * 86400
            if let c = cache.get("month-\(id).json", [Entry].self, maxAge: offline ? nil : fresh) { all += c; continue }
            if offline { continue }
            guard let d = try? await HTTP.get("https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/\(id)", headers: ["Accept": "application/json"]),
                  let j = jsonObject(d) as? [String: Any] else { failed += 1; continue }
            let reduced = reduce(j, month: id)
            cache.put("month-\(id).json", reduced)
            all += reduced
        }
        let st = SourceStatus(name: "Microsoft MSRC", state: wanted.isEmpty || failed > 0 ? .warning : .ok,
                              detail: wanted.isEmpty ? "no monthly releases loaded" : "\(wanted.count) monthly releases, \(all.count) Mac-relevant advisories" + (failed > 0 ? "; \(failed) months failed" : ""),
                              count: all.count, updated: Date())
        return (all, st)
    }

    static func reduce(_ j: [String: Any], month: String) -> [Entry] {
        var names: [String: String] = [:]
        for p in (j["ProductTree"] as? [String: Any])?["FullProductName"] as? [[String: Any]] ?? [] {
            if let id = p["ProductID"] as? String, let v = p["Value"] as? String { names[id] = v }
        }
        let relevant: (String) -> Bool = { n in (n.contains("Mac") && (n.contains("Office") || n.contains("Teams"))) || n.hasPrefix("Microsoft Edge") || n == "Visual Studio Code" }
        var out: [Entry] = []
        for v in j["Vulnerability"] as? [[String: Any]] ?? [] {
            guard let cve = v["CVE"] as? String else { continue }
            var prods = Set<String>(), fixed: [String] = []
            for r in v["Remediations"] as? [[String: Any]] ?? [] {
                let ps = (r["ProductID"] as? [String] ?? []).compactMap { names[$0] }.filter(relevant)
                guard !ps.isEmpty else { continue }
                prods.formUnion(ps)
                if let fb = r["FixedBuild"] as? String, fb.first?.isNumber == true { fixed.append(fb) }
            }
            guard !prods.isEmpty else { continue }
            let threats = (v["Threats"] as? [[String: Any]] ?? []).compactMap { ($0["Description"] as? [String: Any])?["Value"] as? String }
            let exploited = threats.contains { $0.contains("Exploited:Yes") }
            let cvss = (v["CVSSScoreSets"] as? [[String: Any]])?.compactMap { $0["BaseScore"] as? Double }.max()
            out.append(Entry(cve: cve, title: ((v["Title"] as? [String: Any])?["Value"] as? String) ?? "", products: Array(prods),
                             fixed: fixed.uniqued(), exploited: exploited, cvss: cvss, month: month))
        }
        return out
    }

    /// Entries that apply to an installed Microsoft app: product matches and build is below the fix.
    public static func open(_ entries: [Entry], for p: Package) -> [Vulnerability] {
        guard let id = p.bundleID, let rule = products(for: id) else { return [] }
        let installed = p.build ?? p.version
        var out: [Vulnerability] = []
        for e in entries where e.products.contains(where: rule.match) {
            if let hint = rule.titleHint, ["Word", "Excel", "PowerPoint", "Outlook", "OneNote"].contains(where: { e.title.contains($0) }), !e.title.contains(hint) { continue }
            guard let fix = e.fixed.min(by: { Version.less($0, $1) }), Version.compare(installed, fix) < 0 else { continue }
            var v = Vulnerability(id: e.cve)
            v.summary = e.title
            v.cvss = e.cvss
            v.severity = e.cvss.map(Severity.init(score:)) ?? .unknown
            v.fixed = e.fixed.sorted { Version.less($0, $1) }
            v.references = ["https://msrc.microsoft.com/update-guide/vulnerability/\(e.cve)"]
            v.source = "Microsoft MSRC (\(e.month))"
            if e.exploited {
                v.kev = KEVEntry(cveID: e.cve, vendorProject: "Microsoft", product: p.name, vulnerabilityName: e.title, dateAdded: e.month,
                                 shortDescription: "Microsoft marks this as exploited.", requiredAction: "", dueDate: "", knownRansomwareCampaignUse: "", source: "MSRC")
            }
            out.append(v)
        }
        return out
    }
}
