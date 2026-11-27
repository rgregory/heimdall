import Foundation

// The News page as a triage surface: what touches this Mac, what is being exploited, what keeps
// coming back, and what can wait. Everything here is derived from the saved `NewsItem`s at
// display time and never stored, so old reports keep working and rules can change freely.
// `now` and the calendar are passed in, so the day buckets are testable.

// MARK: - Tiers, sections, lanes

/// How urgent one story is for this Mac. Every story gets exactly one, decided top-down.
public enum NewsTier: Int, Codable, CaseIterable, Comparable, Sendable {
    /// Names a CVE that is open on this Mac.
    case affected
    /// Names software installed here (by product name; fuzzier than `affected`).
    case installed
    /// A CVE in CISA's KEV list, or reports of exploitation in the wild.
    case exploited
    /// Cites a CVE or a vulnerability; no exploitation reported.
    case advisory
    /// Malware, phishing, supply-chain poisoning, breaches.
    case campaign
    /// Roundups, podcasts, policy, opinion: everything else.
    case digest

    public static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }

    public var section: NewsSection {
        switch self {
        case .affected, .installed: return .onThisMac
        case .exploited: return .exploited
        case .advisory: return .advisories
        case .campaign: return .campaigns
        case .digest: return .digest
        }
    }
}

/// The page's sections, in display order.
public enum NewsSection: Int, CaseIterable, Comparable, Identifiable, Sendable {
    case onThisMac, exploited, advisories, campaigns, digest

    public var id: Int { rawValue }
    public static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
    public var title: String {
        switch self {
        case .onThisMac: return "On This Mac"
        case .exploited: return "Exploited in the Wild"
        case .advisories: return "Advisories"
        case .campaigns: return "Campaigns, Malware & Breaches"
        case .digest: return "Digests, Policy & Other"
        }
    }
    /// Only the noise drawer starts closed.
    public var collapsedByDefault: Bool { self == .digest }
}

/// Rows of the activity matrix: the front page's desks, plus everything not on this Mac.
public enum NewsLane: Int, CaseIterable, Comparable, Identifiable, Sendable {
    case system, apps, homebrew, languages, elsewhere

    public var id: Int { rawValue }
    public static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
    public init(desk: Desk) {
        switch desk {
        case .system: self = .system
        case .apps: self = .apps
        case .homebrew: self = .homebrew
        case .languages: self = .languages
        }
    }
    public var title: String {
        switch self {
        case .system: return "macOS"
        case .apps: return "Apps"
        case .homebrew: return "Homebrew"
        case .languages: return "Languages"
        case .elsewhere: return "Elsewhere"
        }
    }
}

// MARK: - Domains

/// What kind of system a story is about, for everything that isn't this Mac. Ordered by how
/// close it sits to a Mac user: a vCenter zero-day matters to someone, just not to this laptop.
public enum NewsDomain: Int, CaseIterable, Comparable, Identifiable, Sendable {
    case apple, desktop, developer, ai, cloud, mobile, remote, web, network, datacenter, industrial, general

    public var id: Int { rawValue }
    public static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
    public var title: String {
        switch self {
        case .apple: return "Apple & macOS"
        case .desktop: return "Desktop Apps & Browsers"
        case .developer: return "Developer & Supply Chain"
        case .ai: return "AI Tools & Platforms"
        case .cloud: return "Cloud, SaaS & Identity"
        case .mobile: return "Mobile"
        case .remote: return "Remote Access & MSP"
        case .web: return "Web Servers & CMS"
        case .network: return "Network Edge & VPN"
        case .datacenter: return "Data Center & Virtualization"
        case .industrial: return "Industrial, IoT & Devices"
        case .general: return "Everything Else"
        }
    }
    /// Domains a Mac user runs or signs into, as opposed to servers and appliances someone else runs.
    public var nearThisMac: Bool { self <= .mobile }

    /// Headline words count three times as much as summary words; ties go to the domain nearer
    /// this Mac. AI counts only as a target (an MCP server, a coding assistant), not as the
    /// attacker's tool, which half of this year's headlines mention.
    static let patterns: [NewsDomain: String] = [
        .apple: #"(?i)\b(macos|mac ?os x|ios|ipados|watchos|visionos|safari|webkit|xcode|apple|icloud|airdrop|gatekeeper|xprotect|amos|atomic stealer|poseidon stealer)\b|\bMacs?\b"#,
        .desktop: #"(?i)\b(windows|chrome|chromium|firefox|microsoft edge|thunderbird|microsoft office|office 365|outlook|microsoft (word|excel|teams)|zoom|slack|discord|telegram|signal desktop|1password|lastpass|bitwarden|keepass|password managers?|browser extensions?|browsers?|desktop|endpoints?|7-zip|winrar|notepad\+\+|vlc|adobe (reader|acrobat)|\.net files)\b"#,
        .developer: #"(?i)\b(npm|pypi|nuget|rubygems|crates\.io|hex\.pm|go modules?|maven|packagist|github|gitlab|bitbucket|github actions|ci/cd|pipelines?|repositor(y|ies)|open source|libraries|library|packages?|sdk|vs ?code|visual studio|jetbrains|cursor|open vsx|ide|docker hub|developers?|supply[- ]chain|binary-parser|gnupg|gpgme|openssl|openssh|ghostscript|imagemagick|java\w*shell|log4j|git)\b"#,
        .ai: #"(?i)\b(mcp( servers?)?|model context protocol|prompt injection|claude code|copilot|ollama|hugging ?face|langchain|openrouter|llm (servers?|apps?|gateways?)|ai (servers?|platforms?|hosting|assistants?|chatbots?|coding (tools?|assistants?))|monai|chatgpt (plugins?|accounts?))\b"#,
        .cloud: #"(?i)\b(aws|amazon web services|azure|google cloud|gcp|microsoft 365|m365|entra|okta|salesforce|snowflake|saas|oauth|sso|single sign-on|cloud accounts?|identity|api management|workspace|atlassian cloud|cloudflare)\b"#,
        .mobile: #"(?i)\b(android|iphone|ipad|mobile|smartphones?|google play|app store|whatsapp|sms|smishing|sim swap)\b"#,
        .remote: #"(?i)\b(screenconnect|connectwise|n-able|kaseya|simplehelp|teamviewer|anydesk|rmm|msps?|managed service providers?|remote (desktop|access|support|monitoring)|rdp|mail ?assure)\b"#,
        .web: #"(?i)\b(drupal|wordpress|joomla|magento|prestashop|woocommerce|cms|plugins?|themes?|websites?|web ?sites?|web (apps?|applications?|servers?|shells?)|php|asp\.net|laravel|django|rails|nginx|apache (http|tomcat|struts)|tomcat|struts|iis|geoserver|whmcs|cpanel|optimizely|e-?commerce|sql injection|xss|csrf)\b"#,
        .network: #"(?i)\b(fortinet|forti(os|gate|web|manager|proxy)|ivanti|pulse secure|netscaler|citrix adc|cisco|juniper|palo alto|pan-os|globalprotect|sonicwall|check point|f5|big-ip|zyxel|tp-link|d-link|netgear|gl\.inet|mikrotik|ubiquiti|firewalls?|vpns?|routers?|gateways?|switches|edge devices?|mitel|expressway|pbx|voip|telecoms?|isps?)\b"#,
        .datacenter: #"(?i)\b(vmware|vcenter|esxi|vsphere|hyper-v|proxmox|xenserver|xen|vates|xcp-ng|nutanix|kvm|hypervisors?|veeam|backup servers?|nas|synology|qnap|storage|kubernetes|k8s|containers?|exchange server|sharepoint|active directory|domain controllers?|sap|oracle|servicenow|linux( kernel| servers?)?|servers?|data ?cent(er|re)s?)\b"#,
        .industrial: #"(?i)\b(ics|scada|ot|plcs?|danfoss|siemens|schneider electric|rockwell|honeywell|industrial|iot|smart home|cameras?|dvrs?|tv boxes|medical|hospitals?|cars?|vehicles?|freezers?|fridges?|printers?|kvm devices)\b"#,
    ]
    static let compiled: [NewsDomain: NSRegularExpression] = patterns.compactMapValues { try? NSRegularExpression(pattern: $0) }

    public static func of(_ item: NewsItem) -> NewsDomain {
        func hits(_ d: NewsDomain, _ s: String) -> Int {
            compiled[d]?.numberOfMatches(in: s, range: NSRange(s.startIndex..., in: s)) ?? 0
        }
        var best = NewsDomain.general, score = 0
        for d in allCases where d != .general {
            let n = hits(d, item.title) * 3 + hits(d, item.summary)
            if n > score { best = d; score = n }
        }
        return best
    }
}

// MARK: - Entities

/// Something a story is about that other stories can share: the basis of clustering and recurrence.
public enum NewsKey: Hashable, Comparable, Sendable {
    case cve(String)
    /// Threat actor, ransomware gang or malware family, normalised ("APT28", "Salt Typhoon").
    case actor(String)
    /// A product or platform that keeps coming up in the news ("vCenter", "NGINX").
    case product(String)
    /// An installed package, by package id.
    case package(String)

    public var label: String {
        switch self {
        case .cve(let c): return c
        case .actor(let a): return a
        case .product(let p): return p
        case .package(let id): return NewsKey.packageName(id)
        }
    }
    /// For tie-breaks: a CVE is the most specific thing two stories can share.
    var rank: Int {
        switch self { case .cve: return 0; case .actor: return 1; case .package: return 2; case .product: return 3 }
    }
    public static func < (a: Self, b: Self) -> Bool {
        a.rank != b.rank ? a.rank < b.rank : a.label.lowercased() < b.label.lowercased()
    }

    /// "homebrew:openssh@10.0@/opt/…" → "openssh"; "go:gitleaks>golang.org/x/crypto@…" → "golang.org/x/crypto".
    static func packageName(_ id: String) -> String {
        var s = Substring(id)
        if let c = s.firstIndex(of: ":") { s = s[s.index(after: c)...] }
        if let g = s.lastIndex(of: ">") { s = s[s.index(after: g)...] }
        if let a = s.firstIndex(of: "@") { s = s[..<a] }
        return String(s)
    }
    static func ecosystem(_ id: String) -> Ecosystem? {
        id.split(separator: ":", maxSplits: 1).first.flatMap { Ecosystem(rawValue: String($0)) }
    }
}

// MARK: - Classification

public enum NewsClassifier {
    /// Multi-topic roundups and newsletters. "+ 17 More Stories" has no word boundary before the
    /// "+", so that alternative is anchored on its own.
    static let roundup = #"(?i)\b(threatsday|weekly recap|weekly update|stormcast|week in review|week in security|weekly roundup|roundup|round-up|newsletter|podcast|smashing security|episode \d+)\b|(\+|\band)\s*\d+\s+more\s+stories\b"#
    /// Exploitation reported. "could be exploited" is advisory boilerplate, so "be exploited" is
    /// excluded, and "Zero Day Initiative" is a bug bounty, not a zero-day.
    static let exploited = #"(?i)(?<!be )\bexploited\b|\bexploiting\b|\b(zero|0)[- ]day(?![- ]initiative)|\bin the wild\b|\bactive(ly)? exploit(ed|ation)\b|\bunder attack\b"#
    /// Headlines only: "Hackers Exploit …", "China-Linked Hackers Exploited …". The noun ("Block
    /// Exploits", "proof-of-concept exploit code") is not a report of exploitation.
    static let exploitVerb = #"(?i)(?<!concept )(?<!be )\bexploit(ed|ing)?\b(?! code| kits?| released| available| chains?| prediction)"#
    static let advisory = #"(?i)\b(vulnerabilit(y|ies)|security flaws?|critical flaws?|flaws?|rce|remote code execution|privilege escalation|auth(entication)? bypass|security (update|advisory|bulletin)s?|patch tuesday)\b"#
    static let campaign = #"(?i)\b(supply[- ]chain|malware|malicious|phishing|smishing|vishing|backdoor(ed|s)?|trojan(ized|s)?|ransomware|info-?stealers?|stealers?|botnets?|spyware|rootkits?|wipers?|poison(s|ed|ing)?|typosquat\w*|hijack\w*|breach(ed|es)?|hack(ed|ers?)|leak(s|ed)?|cyber ?attacks?|intrusions?|compromise[ds]?|extortion|espionage|gangs?|campaigns?|threat actors?|apt ?\d+|worm)\b"#
    /// Explainers, opinion and reports: told apart by the headline alone.
    static let explainer = #"(?i)^(how|why|what|is it|my |lessons|the path|when )|\b(what you need to know|explained|playbook|webinar|tips|statistics|activity report|budget|interview|q&a)\b"#
    /// A fix is out. Kept out of the tier: it flags a cluster, it doesn't calm it.
    static let fix = #"(?i)(?<!un)\bpatch(ed|es)\b|\bfix(ed|es)? (is |are )?(now )?(available|released|out)\b|\bfixed in\b|\bupdate now\b|\bsecurity updates? (released|available|out)\b|\bemergency (update|patch)\b"#

    /// Feeds that are commentary or episodes, never advisories.
    static let digestSources = ["Darknet Diaries", "RansomLook", "Schneier on Security"]

    /// Compiled once: the page re-derives everything on each new report, and every story runs
    /// a dozen patterns.
    static let compiled: [String: NSRegularExpression] = {
        var d: [String: NSRegularExpression] = [:]
        for p in [roundup, exploited, exploitVerb, advisory, campaign, explainer, fix, productPattern, securityHeadline] + actorPatterns {
            d[p] = try? NSRegularExpression(pattern: p)
        }
        return d
    }()
    static func rx(_ p: String) -> NSRegularExpression? { compiled[p] ?? (try? NSRegularExpression(pattern: p)) }

    static func matches(_ s: String, _ pattern: String) -> Bool {
        rx(pattern)?.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }
    static func allMatches(_ s: String, _ pattern: String) -> [[String]] {
        guard let r = rx(pattern) else { return [] }
        return r.matches(in: s, range: NSRange(s.startIndex..., in: s)).map { m in
            (0..<m.numberOfRanges).map { i in Range(m.range(at: i), in: s).map { String(s[$0]) } ?? "" }
        }
    }

    /// One tier per story, top-down: an open CVE here first, then noise is set aside (even a name
    /// match), then installed software, then keyword
    /// rules, so a roundup that lists twenty CVEs lands in the digest and not under Exploited.
    public static func tier(_ item: NewsItem, kev: Set<String>) -> NewsTier {
        if item.relevance == .affected { return .affected }
        let title = item.title
        // A product name in a podcast or a twenty-story roundup is a passing mention, not news
        // about your copy. An open CVE (above) still wins over any of this.
        let noise = digestSources.contains(where: { item.source.hasPrefix($0) }) || matches(title, roundup)
        if item.relevance == .installed && !noise && namesInstalledInHeadline(item) { return .installed }
        if noise { return .digest }
        if !kev.isDisjoint(with: item.cves) { return .exploited }
        // The headline says what the story is about; the summary only breaks ties.
        if matches(title, exploited) || matches(title, exploitVerb) { return .exploited }
        if matches(title, advisory) { return .advisory }
        if matches(title, campaign) || NewsClassifier.keys(item, local: false).contains(where: { if case .actor = $0 { return true }; return false }) { return .campaign }
        if matches(title, explainer) { return .digest }
        if !item.cves.isEmpty { return .advisory }
        if matches(item.summary, exploited) { return .exploited }
        if matches(item.summary, advisory) { return .advisory }
        if matches(item.summary, campaign) { return .campaign }
        return .digest
    }

    /// Security words a headline about your software should carry: "Telegram fixes account
    /// takeover" is about your copy; "Months of Prompt Theft at AI Hosting Firms" is not about
    /// Panic's Prompt.
    static let securityHeadline = #"(?i)\b(bugs?|fix(es|ed)?|patch(es|ed)?|updates?|takeover|security|vulnerab\w*|flaws?|cve-\d|exploit\w*|zero[- ]day|0[- ]day|malicious|malware|backdoor\w*|compromise[ds]?|hijack\w*|breach\w*|hack(ed|ers?)|leak(s|ed)?|attacks?|rce|spyware|stealer\w*|trojan\w*|phishing|ransomware|poison\w*|advisory|warns?|spy\w*|spies|espionage|surveillance|scams?)\b"#

    /// A product-name match (not an open CVE) puts a story under On This Mac only when the
    /// headline itself names the product and is about security. Names found only in a summary,
    /// or in a headline about something else, stay as a quiet tag on the story.
    public static func namesInstalledInHeadline(_ item: NewsItem) -> Bool {
        guard matches(item.title, securityHeadline) else { return false }
        let title = " " + item.title.lowercased().replacingOccurrences(of: #"[^a-z0-9.+\- ]"#, with: " ", options: .regularExpression) + " "
        for id in item.packageIDs {
            let name = NewsKey.packageName(id).lowercased()
            var names = [name]
            let parts = name.split(separator: " ")
            if parts.count == 2, News.Matcher.vendors.contains(String(parts[0])) { names.append(String(parts[1])) }   // "google chrome" → "chrome"
            for n in names where !n.isEmpty {
                if title.range(of: #"(?<![a-z0-9])"# + NSRegularExpression.escapedPattern(for: n) + #"(?![a-z0-9])"#, options: .regularExpression) != nil { return true }
            }
        }
        return false
    }

    /// Exploitation signal independent of tier (a story about your Chrome can also be a zero-day).
    public static func isExploited(_ item: NewsItem, kev: Set<String>) -> Bool {
        !kev.isDisjoint(with: item.cves) || matches(item.title, exploitVerb) || matches(item.title + " " + item.summary, exploited)
    }

    public static func mentionsFix(_ item: NewsItem) -> Bool { matches(item.title + " " + item.summary, fix) }

    // Actors: vendor naming schemes are stable, so patterns beat a list that goes stale.
    static let actorPatterns: [String] = [
        #"\b(APT|UNC|FIN|TA)[- ]?\d{1,4}\b"#,
        #"\bStorm-\d{3,4}\b"#,
        #"\b[A-Z][a-z]{2,} (Typhoon|Blizzard|Sandstorm|Sleet|Tempest|Spider|Bear|Panda|Kitten|Chollima)\b"#,
        #"\b(Lazarus|Kimsuky|Turla|Sandworm|LockBit|ALPHV|BlackCat|Black Basta|RansomHub|Qilin|Cl0p|Clop|Rhysida|BianLian|Medusa|Scattered Spider|ShinyHunters|Lumma|RedLine|Emotet|QakBot|IcedID|Shai-Hulud|GlassWorm|Atomic Stealer|AMOS|Poseidon)\b"#,
    ]

    /// Products that are attacked often enough to name waves of news. Names, not versions, so the
    /// list ages slowly; anything installed here is matched by package id as well.
    static let products: [String] = [
        "vCenter", "ESXi", "Ghostscript", "NGINX", "ScreenConnect", "GeoServer", "Drupal", "WordPress", "SharePoint",
        "Exchange Server", "FortiOS", "FortiGate", "FortiWeb", "Ivanti", "NetScaler", "Citrix", "PAN-OS", "GlobalProtect",
        "SonicWall", "Jenkins", "GitLab", "Confluence", "Log4j", "OpenSSH", "OpenSSL", "Chrome", "Firefox", "Safari", "WebKit",
        "WhatsApp", "Signal", "Telegram", "1Password", "LastPass", "Bitwarden", "Okta", "Salesforce", "Snowflake", "MOVEit",
        "Expressway", "Juniper", "Veeam", "Zimbra", "Roundcube", "Tomcat", "Kubernetes", "Docker", "npm", "PyPI", "NuGet",
        "GitHub Actions", "Hex.pm", "N-able", "Xcode", "Homebrew", "VS Code", "Cursor", "Ollama", "Zoom", "Slack",
    ]
    static let productPattern: String = "\\b(" + products.map(NSRegularExpression.escapedPattern(for:)).joined(separator: "|") + ")(?![A-Za-z0-9])"

    /// CVEs, actors, products and installed packages a story names. Packages count only for stories
    /// about this Mac (a passing name match shouldn't build a cluster), and macOS itself is left
    /// out: nearly every Apple story names it, so it would glue unrelated stories together.
    public static func keys(_ item: NewsItem, local: Bool = true) -> [NewsKey] {
        var out: [NewsKey] = item.cves.map { .cve($0.uppercased()) }
        let hay = item.title + " " + item.summary
        for p in actorPatterns {
            for m in allMatches(hay, p) { out.append(.actor(normaliseActor(m[0]))) }
        }
        for m in allMatches(hay, productPattern) { out.append(.product(m[1])) }
        if local { for id in item.packageIDs where NewsKey.ecosystem(id) != .macos { out.append(.package(id)) } }
        return out.uniqued()
    }

    static func normaliseActor(_ s: String) -> String {
        if s.first?.isUppercase == true, let m = s.firstMatch(#"^(APT|UNC|FIN|TA)[- ]?(\d+)$"#) { return m[1] + m[2] }
        if s == "Clop" { return "Cl0p" }
        if s == "BlackCat" { return "ALPHV" }
        return s
    }
}

// MARK: - Analysed stories and units

public struct NewsStory: Identifiable, Hashable, Sendable {
    public var item: NewsItem
    public var tier: NewsTier
    /// 0 = 29 days ago … 29 = today. nil when undated or outside the window.
    public var day: Int?
    public var lanes: Set<NewsLane>
    public var keys: [NewsKey]
    public var exploited: Bool
    public var fix: Bool
    public var domain: NewsDomain
    public var id: String { item.id }
    public var published: Date? { item.published }
    /// What the Exploited card and filter count: the Exploited section, plus stories about this
    /// Mac that report exploitation. A word in a digest or an advisory's summary doesn't count.
    public var countsAsExploited: Bool { tier == .exploited || (tier <= .installed && exploited) }
}

public struct NewsRecurrence: Hashable, Sendable {
    public var key: NewsKey
    /// Distinct days the key has been in the news, counting this one.
    public var ordinal: Int
    public var text: String { "\(ordinalString(ordinal)) mention · 30d" }
}

/// How a multi-story cluster is moving.
public enum NewsStage: String, Sendable {
    case exploited, escalating, new, ongoing
    public var title: String {
        switch self {
        case .exploited: return "EXPLOITED"
        case .escalating: return "ESCALATING"
        case .new: return "NEW"
        case .ongoing: return "ONGOING"
        }
    }
}

/// What the feed shows as one row: a single story, or a cluster of stories about one thing.
public struct NewsUnit: Identifiable, Hashable, Sendable {
    public var id: String
    /// Newest first. After filtering, only the stories that match.
    public var stories: [NewsStory]
    /// All stories in the cluster, before filtering.
    public var total: Int
    public var tier: NewsTier
    public var stage: NewsStage
    public var fix: Bool
    /// The key the cluster formed around ("CVE-2026-1234", "Salt Typhoon", "openssh").
    public var key: NewsKey?
    /// Stories per day over the seven days ending on the cluster's latest day, oldest first.
    public var velocity: [Int]
    public var sources: Int
    public var recurrence: NewsRecurrence?
    /// The domain most of its stories are about (the lead story's, on a tie).
    public var domain: NewsDomain

    public var isCluster: Bool { total >= 2 }
    public var latest: Date? { stories.compactMap(\.published).max() }
    public var section: NewsSection { tier.section }
    public var lead: NewsStory { stories[0] }
}

public struct NewsSectionGroup: Identifiable, Sendable {
    public var section: NewsSection
    public var units: [NewsUnit]
    public var id: Int { section.rawValue }
    public var storyCount: Int { units.reduce(0) { $0 + $1.stories.count } }

    /// Whether the section is split by domain: everything that isn't about this Mac or noise.
    public var groupsByDomain: Bool { section != .onThisMac && section != .digest }

    /// The section's units by domain, nearest this Mac first, newest first inside each.
    public var byDomain: [NewsDomainGroup] {
        Dictionary(grouping: units, by: \.domain)
            .map { NewsDomainGroup(section: section, domain: $0.key, units: $0.value) }
            .sorted { $0.domain < $1.domain }
    }
}

public struct NewsDomainGroup: Identifiable, Sendable {
    public var section: NewsSection
    public var domain: NewsDomain
    public var units: [NewsUnit]
    public var id: String { "\(section.rawValue)-\(domain.rawValue)" }
    public var storyCount: Int { units.reduce(0) { $0 + $1.stories.count } }
}

// MARK: - Telemetry and matrix

public enum NewsTrend: Hashable, Sendable {
    /// Nothing in either week.
    case none
    /// Nothing last week, something this week.
    case new
    /// Small numbers: an absolute change reads better than "+200%".
    case delta(Int)
    case percent(Int)

    /// This week (days 23…29) against the week before (16…22). Until last week had five stories
    /// the change is shown as a count rather than a percentage.
    public static func of(_ buckets: [Int]) -> NewsTrend {
        guard buckets.count == 30 else { return .none }
        let cur = buckets[23...29].reduce(0, +), prev = buckets[16...22].reduce(0, +)
        if prev == 0 { return cur == 0 ? .none : .new }
        if prev < 5 { return .delta(cur - prev) }   // 1 → 16 reads as "+15", not "+1500%"
        return .percent(Int((Double(cur - prev) / Double(prev) * 100).rounded()))
    }
    public var rising: Bool {
        switch self { case .new: return true; case .delta(let d): return d > 0; case .percent(let p): return p > 0; case .none: return false }
    }
    public var text: String? {
        switch self {
        case .none: return nil
        case .new: return "New"
        case .delta(let d): return d == 0 ? "±0" : (d > 0 ? "+\(d)" : "\(d)")
        case .percent(let p): return p == 0 ? "±0%" : (p > 0 ? "+\(p)%" : "\(p)%")
        }
    }
}

public struct NewsMetric: Identifiable, Sendable {
    public enum Kind: String, CaseIterable, Sendable { case onThisMac, exploited, volume }
    public var kind: Kind
    public var total: Int
    /// 30 days, index 0 = 29 days ago, 29 = today.
    public var buckets: [Int]
    public var trend: NewsTrend
    public var id: Kind { kind }
    public var title: String {
        switch kind {
        case .onThisMac: return "About This Mac"
        case .exploited: return "Exploited"
        case .volume: return "30-Day Volume"
        }
    }
}

public struct NewsCell: Identifiable, Hashable, Sendable {
    public var lane: NewsLane
    public var day: Int
    public var date: Date
    public var count: Int
    /// Stories naming an open CVE here.
    public var affected: Int
    /// Stories naming installed software (affected or installed).
    public var local: Int
    public var exploited: Int
    public var id: String { "\(lane.rawValue)-\(day)" }
}

// MARK: - Filter

public enum NewsFilter: Hashable, Sendable {
    case none
    case onThisMac
    case exploited
    case lane(NewsLane)
    case day(Int)
    case cell(day: Int, lane: NewsLane)

    public func matches(_ s: NewsStory) -> Bool {
        switch self {
        case .none: return true
        case .onThisMac: return s.tier <= .installed
        case .exploited: return s.countsAsExploited
        case .lane(let l): return s.lanes.contains(l)
        case .day(let d): return s.day == d
        case .cell(let d, let l): return s.day == d && s.lanes.contains(l)
        }
    }
    public var day: Int? {
        switch self { case .day(let d), .cell(let d, _): return d; default: return nil }
    }
    public var lane: NewsLane? {
        switch self { case .lane(let l), .cell(_, let l): return l; default: return nil }
    }
}

// MARK: - The analysis

public struct NewsAnalysis: Sendable {
    public static let windowDays = 30
    static let clusterWindow: TimeInterval = 7 * 86400
    /// A key in more stories than this is a topic, not an event: it doesn't form clusters.
    static let maxClusterKeyStories = 12

    public var now: Date
    /// Start of each day in the window, oldest first.
    public var days: [Date]
    public var stories: [NewsStory]
    public var units: [NewsUnit]
    public var metrics: [NewsMetric]
    public var matrix: [NewsLane: [NewsCell]]

    /// Straight from a report: KEV CVEs come from the timeline and the findings.
    public init(report: ScanReport, now: Date = Date(), calendar: Calendar = .current) {
        var kev = Set(report.timeline?.map(\.cve) ?? [])
        for f in report.findings { for v in f.vulns where v.isKEV { kev.formUnion(v.cves) } }
        self.init(news: report.news ?? [], kev: kev, now: now, calendar: calendar)
    }

    public init(news: [NewsItem], kev: Set<String>, now: Date = Date(), calendar: Calendar = .current) {
        self.now = now
        let today = calendar.startOfDay(for: now)
        days = (0..<Self.windowDays).map { calendar.date(byAdding: .day, value: $0 - (Self.windowDays - 1), to: today) ?? today }

        func dayIndex(_ d: Date?) -> Int? {
            guard let d else { return nil }
            let n = calendar.dateComponents([.day], from: calendar.startOfDay(for: d), to: today).day ?? 0
            let i = Self.windowDays - 1 - max(0, n)     // a little clock skew into tomorrow counts as today
            return (0..<Self.windowDays).contains(i) ? i : nil
        }

        stories = news.map { item in
            let lanes: Set<NewsLane> = item.relevance == .general || item.packageIDs.isEmpty
                ? [.elsewhere]
                : Set(item.packageIDs.map { NewsKey.ecosystem($0).map { NewsLane(desk: $0.desk) } ?? .apps })
            let tier = NewsClassifier.tier(item, kev: kev)
            return NewsStory(item: item, tier: tier, day: dayIndex(item.published), lanes: lanes,
                             keys: NewsClassifier.keys(item, local: tier <= .installed), exploited: NewsClassifier.isExploited(item, kev: kev),
                             fix: NewsClassifier.mentionsFix(item), domain: NewsDomain.of(item))
        }
        units = Self.cluster(stories, now: now)
        metrics = Self.metrics(stories)
        matrix = Self.matrix(stories, days: days)
    }

    // MARK: clustering

    /// Stories sharing a CVE, actor or installed package within seven days of each other join one
    /// cluster. Links chain (A–B and B–C put all three together), so a long-running story stays one
    /// card. Undated stories never cluster.
    static func cluster(_ stories: [NewsStory], now: Date) -> [NewsUnit] {
        var parent = Array(stories.indices)
        func find(_ i: Int) -> Int { var i = i; while parent[i] != i { parent[i] = parent[parent[i]]; i = parent[i] }; return i }
        func union(_ a: Int, _ b: Int) { let (x, y) = (find(a), find(b)); if x != y { parent[max(x, y)] = min(x, y) } }

        var byKey: [NewsKey: [Int]] = [:]
        for (i, s) in stories.enumerated() where s.published != nil && s.day != nil { for k in s.keys { byKey[k, default: []].append(i) } }
        var formedBy: [Int: NewsKey] = [:]
        for k in byKey.keys.sorted() {
            let idx = byKey[k]!
            guard idx.count >= 2, idx.count <= maxClusterKeyStories else { continue }
            let sorted = idx.sorted { stories[$0].published! < stories[$1].published! }
            for (a, b) in zip(sorted, sorted.dropFirst()) where stories[b].published!.timeIntervalSince(stories[a].published!) <= clusterWindow {
                if find(a) != find(b) { formedBy[min(find(a), find(b))] = formedBy[min(find(a), find(b))] ?? k }
                union(a, b)
            }
        }

        // The same story syndicated twice ("Operation X" on two feeds) is one story.
        var byTitle: [String: Int] = [:]
        for (i, s) in stories.enumerated() where s.day != nil {
            let t = s.item.title.lowercased().filter { $0.isLetter || $0.isNumber }
            guard t.count >= 12 else { continue }
            if let j = byTitle[t] { union(i, j) } else { byTitle[t] = i }
        }

        var groups: [Int: [Int]] = [:]
        for i in stories.indices { groups[find(i), default: []].append(i) }

        let units: [NewsUnit] = groups.map { root, idx in
            let members = idx.map { stories[$0] }.sorted(by: newestFirst)
            let oldest = members.last!
            let key: NewsKey? = members.count >= 2 ? (formedBy[root] ?? sharedKey(members)) : nil
            return NewsUnit(id: (members.count >= 2 ? "cluster-" : "") + oldest.id, stories: members, total: members.count,
                            tier: members.map(\.tier).min()!, stage: stage(members, now: now), fix: members.contains(where: \.fix),
                            key: key, velocity: velocity(members), sources: Set(members.map(\.item.source)).count, recurrence: nil,
                            domain: majorityDomain(members))
        }
        return recurrence(units)
    }

    static func newestFirst(_ a: NewsStory, _ b: NewsStory) -> Bool {
        let (x, y) = (a.published ?? .distantPast, b.published ?? .distantPast)
        return x != y ? x > y : a.id < b.id
    }

    static func majorityDomain(_ members: [NewsStory]) -> NewsDomain {
        var n: [NewsDomain: Int] = [:]
        for s in members { n[s.domain, default: 0] += 1 }
        let top = n.values.max() ?? 0
        let lead = members[0].domain
        return n[lead] == top ? lead : n.filter { $0.value == top }.keys.min() ?? lead
    }

    static func sharedKey(_ members: [NewsStory]) -> NewsKey? {
        var n: [NewsKey: Int] = [:]
        for s in members { for k in s.keys { n[k, default: 0] += 1 } }
        return n.filter { $0.value >= 2 }.sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }.first?.key
    }

    /// Exploited beats escalating beats new: being exploited is the fact that changes what you do.
    /// Escalating means more stories in the last two days than in the five before, or three outlets
    /// at once in the last two days.
    static func stage(_ members: [NewsStory], now: Date) -> NewsStage {
        if members.contains(where: \.countsAsExploited) { return .exploited }
        let dates = members.compactMap(\.published)
        let recent = members.filter { ($0.published ?? .distantPast) >= now.addingTimeInterval(-2 * 86400) }
        let prior = dates.filter { $0 < now.addingTimeInterval(-2 * 86400) && $0 >= now.addingTimeInterval(-7 * 86400) }.count
        if recent.count >= 2 && recent.count > prior && prior > 0 { return .escalating }
        if Set(recent.map(\.item.source)).count >= 3 && prior > 0 { return .escalating }
        if let first = dates.min(), first >= now.addingTimeInterval(-2 * 86400) { return .new }
        return .ongoing
    }

    static func velocity(_ members: [NewsStory]) -> [Int] {
        let days = members.compactMap(\.day)
        guard let last = days.max() else { return Array(repeating: 0, count: 7) }
        return (0..<7).map { off in days.filter { $0 == last - 6 + off }.count }
    }

    /// For each unit, the key it shares with earlier, separate news: how many distinct days that
    /// key has been in the news up to and including this unit. Keys only seen inside the unit
    /// itself don't count — the cluster already says that.
    static func recurrence(_ units: [NewsUnit]) -> [NewsUnit] {
        var daysByKey: [NewsKey: [(day: Int, unit: String)]] = [:]
        for u in units { for s in u.stories { guard let d = s.day else { continue }; for k in s.keys { daysByKey[k, default: []].append((d, u.id)) } } }
        return units.map { u in
            var u = u
            guard u.tier != .digest, let first = u.stories.compactMap(\.day).min() else { return u }
            let keys = Set(u.stories.flatMap(\.keys))
            var best: NewsRecurrence?
            for k in keys.sorted() {
                let before = Set((daysByKey[k] ?? []).filter { $0.unit != u.id && $0.day < first }.map(\.day))
                guard !before.isEmpty else { continue }
                let r = NewsRecurrence(key: k, ordinal: before.count + 1)
                if best == nil || r.ordinal > best!.ordinal { best = r }
            }
            u.recurrence = best
            return u
        }
    }

    // MARK: telemetry

    static func metrics(_ stories: [NewsStory]) -> [NewsMetric] {
        NewsMetric.Kind.allCases.map { kind in
            let filter: NewsFilter = kind == .onThisMac ? .onThisMac : kind == .exploited ? .exploited : .none
            let picked = stories.filter(filter.matches)
            var b = Array(repeating: 0, count: windowDays)
            for s in picked { if let d = s.day { b[d] += 1 } }
            return NewsMetric(kind: kind, total: picked.count, buckets: b, trend: .of(b))
        }
    }

    static func matrix(_ stories: [NewsStory], days: [Date]) -> [NewsLane: [NewsCell]] {
        var out: [NewsLane: [NewsCell]] = [:]
        for lane in NewsLane.allCases {
            out[lane] = days.indices.map { d in
                let here = stories.filter { $0.day == d && $0.lanes.contains(lane) }
                return NewsCell(lane: lane, day: d, date: days[d], count: here.count,
                                affected: here.filter { $0.tier == .affected }.count,
                                local: here.filter { $0.tier <= .installed }.count,
                                exploited: here.filter(\.countsAsExploited).count)
            }
        }
        return out
    }

    // MARK: output

    /// Sections in order, each unit trimmed to the stories that pass the filter and search.
    /// On This Mac puts open CVEs ahead of name matches; every section is newest first after that.
    public func sections(filter: NewsFilter = .none, search: String = "") -> [NewsSectionGroup] {
        let q = search.trimmed.lowercased()
        func passes(_ s: NewsStory) -> Bool {
            guard filter.matches(s) else { return false }
            guard !q.isEmpty else { return true }
            let i = s.item
            return (i.title + " " + i.summary + " " + i.source + " " + i.cves.joined(separator: " ") + " " + i.mentions.joined(separator: " "))
                .lowercased().contains(q)
        }
        var bySection: [NewsSection: [NewsUnit]] = [:]
        for u in units {
            var u = u
            u.stories = u.stories.filter(passes)
            guard !u.stories.isEmpty else { continue }
            bySection[u.section, default: []].append(u)
        }
        return NewsSection.allCases.map { sec in
            let list = (bySection[sec] ?? []).sorted { a, b in
                if sec == .onThisMac, a.tier != b.tier { return a.tier < b.tier }
                let (x, y) = (a.latest ?? .distantPast, b.latest ?? .distantPast)
                return x != y ? x > y : a.id < b.id
            }
            return NewsSectionGroup(section: sec, units: list)
        }
    }

    public func metric(_ k: NewsMetric.Kind) -> NewsMetric? { metrics.first { $0.kind == k } }
    public func count(_ filter: NewsFilter) -> Int { stories.filter(filter.matches).count }
}

/// "1st", "2nd", "3rd", "11th", "22nd".
public func ordinalString(_ n: Int) -> String {
    let suffix: String
    switch (n % 10, n % 100) {
    case (_, 11...13): suffix = "th"
    case (1, _): suffix = "st"
    case (2, _): suffix = "nd"
    case (3, _): suffix = "rd"
    default: suffix = "th"
    }
    return "\(n)\(suffix)"
}
