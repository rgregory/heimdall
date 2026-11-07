import Foundation

/// Security news, matched to this Mac: a story is "affected" when it names a CVE that's open
/// here, "installed" when it names software you have (by CVE or product name), else "general".
public struct NewsItem: Codable, Hashable, Identifiable, Sendable {
    public enum Relevance: String, Codable, Sendable { case affected, installed, general }
    public var title: String
    public var link: String
    public var source: String
    public var published: Date?
    public var summary: String
    public var cves: [String]
    public var relevance: Relevance = .general
    /// "Google Chrome 142.0", or "CVE-2026-1234 (Google Chrome)".
    public var mentions: [String] = []
    public var packageIDs: [String] = []
    public var id: String { link.isEmpty ? source + title : link }
}

public struct NewsFeed: Codable, Hashable, Sendable {
    public var name: String
    public var url: String
    public init(name: String, url: String) { self.name = name; self.url = url }

    public static let defaults: [NewsFeed] = [
        NewsFeed(name: "SANS ISC", url: "https://isc.sans.edu/rssfeed_full.xml"),
        NewsFeed(name: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews?format=xml"),
        NewsFeed(name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/"),
        NewsFeed(name: "Sophos Threat Research", url: "https://news.sophos.com/en-us/category/threat-research/feed/"),
        NewsFeed(name: "Sophos Security Operations", url: "https://news.sophos.com/en-us/category/security-operations/feed/"),
        NewsFeed(name: "Securelist", url: "https://securelist.com/feed/"),
        NewsFeed(name: "WeLiveSecurity", url: "https://feeds.feedburner.com/eset/blog"),
        NewsFeed(name: "Schneier on Security", url: "https://www.schneier.com/feed/atom/"),
        NewsFeed(name: "Troy Hunt", url: "https://www.troyhunt.com/rss/"),
        NewsFeed(name: "Graham Cluley", url: "https://grahamcluley.com/feed/"),
        NewsFeed(name: "Darknet Diaries", url: "https://podcast.darknetdiaries.com/"),
        NewsFeed(name: "USOM (TR-CERT) duyuru", url: "https://www.usom.gov.tr/rss/duyuru.rss"),
        NewsFeed(name: "USOM (TR-CERT) tehdit", url: "https://www.usom.gov.tr/rss/tehdit.rss"),
    ]

    /// Feeds dropped from the defaults; removed from saved settings too.
    public static let retired: Set<String> = ["https://www.ransomlook.io/rss.xml"]
}

public enum News {
    /// Fetch every feed (cached an hour), keep the last `days`, match against this Mac.
    public static func load(feeds: [NewsFeed], packages: [Package], findings: [Finding], days: Int = 30, offline: Bool) async -> ([NewsItem], SourceStatus) {
        let cache = DiskCache("news")
        let results: [(NewsFeed, [NewsItem]?)] = await concurrentMap(feeds, width: 6) { f in
            let key = "feed-" + stableHash(f.url) + ".xml"
            var d = cache.data(key, maxAge: offline ? nil : 3600)
            if d == nil && !offline {
                d = try? await HTTP.get(f.url, headers: ["Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.5"])
                if let d { cache.store(key, d) } else { d = cache.data(key) }   // stale beats nothing
            }
            guard let d else { return (f, nil) }
            return (f, parse(String(decoding: d, as: UTF8.self), source: f.name))
        }
        let cutoff = Date().addingTimeInterval(-Double(days) * 86400)
        var items: [NewsItem] = []
        var failed: [String] = []
        for (f, list) in results {
            guard let list else { failed.append(f.name); continue }
            items += list.filter { ($0.published ?? .distantPast) >= cutoff }.prefix(60)
        }
        let matcher = Matcher(packages: packages, findings: findings)
        items = items.map(matcher.match).sorted { ($0.published ?? .distantPast) > ($1.published ?? .distantPast) }
        var seen = Set<String>()
        items = items.filter { seen.insert($0.id).inserted }
        let mine = items.filter { $0.relevance != .general }.count
        let st = SourceStatus(name: "News", state: failed.isEmpty ? .ok : (failed.count == feeds.count ? .failed : .warning),
                              detail: "\(feeds.count - failed.count) of \(feeds.count) feeds, \(items.count) stories in \(days) days, \(mine) about this Mac"
                                + (failed.isEmpty ? "" : "; no answer from \(failed.joined(separator: ", "))"),
                              count: items.count, updated: Date())
        return (items, st)
    }

    // MARK: parsing (RSS 2.0 and Atom)

    public static func parse(_ xml: String, source: String) -> [NewsItem] {
        let isAtom = xml.range(of: "<feed", options: .caseInsensitive) != nil && xml.range(of: "<entry", options: .caseInsensitive) != nil
        let blocks = xml.allMatches(isAtom ? #"<entry[\s>]([\s\S]*?)</entry>"# : #"<item[\s>]([\s\S]*?)</item>"#, options: .caseInsensitive).map { $0[1] }
        return blocks.compactMap { b in
            let title = text(tag(b, "title"))
            guard !title.isEmpty else { return nil }
            var link = isAtom ? (b.firstMatch(#"<link[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)"#)?[1] ?? b.firstMatch(#"<link[^>]*href=["']([^"']+)"#)?[1] ?? "")
                              : text(tag(b, "link"))
            if link.isEmpty { link = text(tag(b, "guid")) }
            let dateStr = text(tag(b, "pubDate") ?? tag(b, "published") ?? tag(b, "updated") ?? tag(b, "dc:date"))
            let body = text(tag(b, "description") ?? tag(b, "summary") ?? tag(b, "content:encoded") ?? tag(b, "content"))
            let full = text(tag(b, "content:encoded") ?? tag(b, "content")) + " " + body
            let cves = (title + " " + full).allMatches(#"CVE-\d{4}-\d{4,}"#, options: .caseInsensitive).map { $0[0].uppercased() }.uniqued()
            return NewsItem(title: title, link: link, source: source, published: date(dateStr), summary: String(body.prefix(420)), cves: cves)
        }
    }

    static func tag(_ s: String, _ name: String) -> String? {
        let n = NSRegularExpression.escapedPattern(for: name)
        return s.firstMatch("<\(n)(?:\\s[^>]*)?>([\\s\\S]*?)</\(n)>", options: .caseInsensitive)?[1]
    }

    /// CDATA, HTML tags and entities out; whitespace collapsed.
    static func text(_ s: String?) -> String {
        guard var t = s else { return "" }
        t = t.replacingOccurrences(of: #"<!\[CDATA\[([\s\S]*?)\]\]>"#, with: "$1", options: .regularExpression)
        for (a, b) in [("&lt;", "<"), ("&gt;", ">"), ("&quot;", "\""), ("&#39;", "'"), ("&#039;", "'"), ("&apos;", "'"), ("&nbsp;", " "),
                       ("&#8217;", "’"), ("&#8216;", "‘"), ("&#8220;", "“"), ("&#8221;", "”"), ("&#8211;", "–"), ("&#8212;", "—"), ("&#8230;", "…"), ("&amp;", "&")] {
            t = t.replacingOccurrences(of: a, with: b)
        }
        t = t.replacingOccurrences(of: #"<[^>]+>"#, with: " ", options: .regularExpression)
        t = t.replacingOccurrences(of: "&amp;", with: "&")
        return t.replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression).trimmed
    }

    static let rfc822: [DateFormatter] = ["EEE, dd MMM yyyy HH:mm:ss Z", "EEE, dd MMM yyyy HH:mm:ss zzz", "dd MMM yyyy HH:mm:ss Z", "EEE, d MMM yyyy HH:mm Z"].map {
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = $0; return f
    }
    static func date(_ s: String) -> Date? {
        guard !s.isEmpty else { return nil }
        return parseDate(s) ?? rfc822.lazy.compactMap { $0.date(from: s) }.first
    }

    // MARK: matching

    struct Matcher {
        var openCVE: [String: [Finding]] = [:]
        /// (lower-cased name to look for, package) — apps, Homebrew, casks, extensions, macOS/Safari.
        var names: [(String, Package)] = []

        static let common: Set<String> = ["word", "mail", "notes", "music", "photos", "books", "messages", "preview", "calendar", "reminders",
                                          "maps", "news", "stocks", "home", "keynote", "pages", "numbers", "find", "rich", "click", "requests",
                                          "six", "wheel", "pip", "setuptools", "packaging", "certifi", "idna", "git", "make", "core", "tree",
                                          "watch", "less", "jq", "wget", "curl", "open", "ruby", "python", "node", "go", "rust", "java", "docker",
                                          "terminal", "slack", "zoom", "signal", "teams", "edge", "arc", "notion", "bear", "things", "spark",
                                          "magnet", "raycast", "alfred", "postman", "hermes", "gemini", "parallels",
                                          "container", "watchman", "glow", "tree", "fish", "starship"]

        static let vendors: Set<String> = ["google", "microsoft", "mozilla", "adobe", "apple", "cisco", "vmware", "oracle", "jetbrains", "brave"]

        /// Ordinary English words ("container", "watchman", "things") make poor product names to search
        /// prose for. macOS ships a word list; elsewhere the built-in stop list has to do.
        static let dictionary: Set<String> = {
            guard let t = try? String(contentsOfFile: "/usr/share/dict/words", encoding: .utf8) else { return [] }
            return Set(t.split(separator: "\n").map { $0.lowercased() })
        }()
        static func isWord(_ n: String) -> Bool { common.contains(n) || dictionary.contains(n) }

        init(packages: [Package], findings: [Finding]) {
            for f in findings { for v in f.vulns { for c in v.cves { openCVE[c, default: []].append(f) } } }
            for p in packages {
                switch p.ecosystem {
                case .macos: names.append(("macos", p))
                case .app where AppCollector.isApple(p): continue
                case .app, .cask, .homebrew, .browserExtension:
                    guard p.parent == nil else { continue }
                    let n = p.name.lowercased().replacingOccurrences(of: #"@.*$"#, with: "", options: .regularExpression).trimmed
                    // Distinctive names only: long enough, not a common word. Short-but-distinctive
                    // vendors (Zoom, Slack, Docker) are still matched via their full "Vendor Product" form below.
                    // Apps ("Safari", "Chrome") are fine as plain words; CLI tools and extensions
                    // ("container", "watchman") must not be dictionary words.
                    let wordy = p.ecosystem == .app ? Self.common.contains(n) : Self.isWord(n)
                    if n.count >= 5, !n.contains(" "), !wordy { names.append((n, p)) }
                    let parts = n.split(separator: " ")
                    if parts.count >= 2 { names.append((n, p)) }   // "google chrome", "microsoft word"
                    // "Google Chrome" → also "chrome"; only for big vendors, so "uBlock Origin" doesn't become "origin".
                    if parts.count == 2, Self.vendors.contains(String(parts[0])), parts[1].count >= 5, !Self.common.contains(String(parts[1])) {
                        names.append((String(parts[1]), p))
                    }
                default: continue
                }
            }
            // Common-word apps still match when the article names them with the vendor.
            for p in packages where p.ecosystem == .app {
                switch p.bundleID ?? "" {
                case "us.zoom.xos": names.append(("zoom", p))
                case "com.tinyspeck.slackmacgap": names.append(("slack", p))
                case "com.docker.docker": names.append(("docker desktop", p))
                case "com.microsoft.teams2", "com.microsoft.teams": names.append(("microsoft teams", p))
                case "com.microsoft.edgemac": names.append(("microsoft edge", p))
                case "org.whispersystems.signal-desktop": names.append(("signal desktop", p))
                default: break
                }
            }
        }

        /// Feeds whose items are about victims or episodes, not software: shown, never matched.
        static let unmatched = ["RansomLook", "Darknet Diaries"]

        func match(_ item: NewsItem) -> NewsItem {
            var it = item
            if Self.unmatched.contains(where: { item.source.hasPrefix($0) }) { return it }
            var ids: [String] = [], mentions: [String] = []
            for c in item.cves {
                if let fs = openCVE[c] {
                    it.relevance = .affected
                    for f in fs { ids.append(f.package.id); mentions.append("\(c) (\(f.package.displayName))") }
                }
            }
            if it.relevance != .affected {
                let hay = " " + (item.title + " " + item.summary).lowercased().replacingOccurrences(of: #"[^a-z0-9.+\- ]"#, with: " ", options: .regularExpression) + " "
                for (n, p) in names where !ids.contains(p.id) {
                    if hay.range(of: #"(?<![a-z0-9])"# + NSRegularExpression.escapedPattern(for: n) + #"(?![a-z0-9])"#, options: .regularExpression) != nil {
                        ids.append(p.id); mentions.append(p.ecosystem == .macos ? "macOS \(p.version)" : "\(p.displayName) \(p.version)")
                    }
                }
                if !ids.isEmpty { it.relevance = .installed }
            }
            it.packageIDs = ids.uniqued(); it.mentions = mentions.uniqued()
            return it
        }
    }
}
