import XCTest
@testable import HeimdallCore

final class NewsAnalysisTests: XCTestCase {
    var cal: Calendar = { var c = Calendar(identifier: .gregorian); c.timeZone = TimeZone(identifier: "UTC")!; return c }()
    /// Thu 26 Nov 2026, 15:00 UTC.
    let now = Date(timeIntervalSince1970: 1795705200)

    func ago(_ days: Double) -> Date { now.addingTimeInterval(-days * 86400) }

    func item(_ title: String, _ cves: [String] = [], days: Double? = 0, source: String = "The Hacker News",
              relevance: NewsItem.Relevance = .general, packages: [String] = [], summary: String = "") -> NewsItem {
        var i = NewsItem(title: title, link: "https://x.test/" + title.replacingOccurrences(of: " ", with: "-") + "\(days ?? -1)",
                         source: source, published: days.map(ago), summary: summary, cves: cves)
        i.relevance = relevance; i.packageIDs = packages
        return i
    }

    func analyse(_ items: [NewsItem], kev: Set<String> = []) -> NewsAnalysis {
        NewsAnalysis(news: items, kev: kev, now: now, calendar: cal)
    }

    // MARK: tiers

    func testTierPrecedence() {
        let kev: Set<String> = ["CVE-2026-0001"]
        func t(_ i: NewsItem) -> NewsTier { NewsClassifier.tier(i, kev: kev) }
        XCTAssertEqual(t(item("Chrome zero-day", ["CVE-2026-0001"], relevance: .affected)), .affected)
        XCTAssertEqual(t(item("ThreatsDay Bulletin: Chrome and 17 More Stories", relevance: .installed)), .digest,
                       "a name in a roundup is a passing mention")
        XCTAssertEqual(t(item("Smashing Security podcast #494: spying from Starbucks", source: "Graham Cluley", relevance: .installed)), .digest)
        XCTAssertEqual(t(item("ThreatsDay Bulletin: Chrome and 17 More Stories", ["CVE-2026-0001"], relevance: .affected)), .affected,
                       "an open CVE here is never hidden in the digest")
        let telegram = ["app:Telegram@13.1.0@/Applications/Telegram.app"]
        XCTAssertEqual(t(item("Telegram fixes account takeover", relevance: .installed, packages: telegram)), .installed)
        XCTAssertEqual(t(item("Spies use Telegram bots", relevance: .installed, packages: telegram)), .installed)
        XCTAssertEqual(t(item("Months of Prompt Theft at AI Hosting Firms", relevance: .installed,
                              packages: ["app:Prompt@3.1@/Applications/Prompt 3.app"])), .digest, "no security words: not about the app")
        XCTAssertEqual(t(item("Here's Why Data Breach Disclosure is so Hard", relevance: .installed,
                              packages: ["app:Claude@6.2@/Applications/Claude.app"], summary: "I asked Claude.")), .campaign,
                       "named only in the summary: classified on its own merits")
        XCTAssertEqual(t(item("Chrome zero-day patched", relevance: .installed,
                              packages: ["app:Google Chrome@142@/Applications/Google Chrome.app"])), .installed, "vendor prefix dropped")
        XCTAssertEqual(t(item("ThreatsDay Bulletin: Chrome Zero-Day and 17 More Stories", ["CVE-2026-0001"])), .digest,
                       "roundups go to the digest before keyword rules")
        XCTAssertEqual(t(item("Weekly bulletin + 12 More Stories")), .digest, "'+ N more stories' matches without a word boundary")
        XCTAssertEqual(t(item("Fortinet flaw added to catalog", ["CVE-2026-0001"])), .exploited, "a KEV CVE is exploited")
        XCTAssertEqual(t(item("Ivanti bug", ["CVE-2026-0002"])), .advisory, "a CVE alone is an advisory, not an exploit")
        XCTAssertEqual(t(item("Router flaw", summary: "The flaw could be exploited to run code.")), .advisory)
        XCTAssertEqual(t(item("Bug reported through Zero Day Initiative", ["CVE-2026-0003"])), .advisory)
        XCTAssertEqual(t(item("Hackers exploiting SharePoint servers")), .exploited)
        XCTAssertEqual(t(item("Hackers Exploit 10 Vulnerabilities Across Mitel and Juniper")), .exploited)
        XCTAssertEqual(t(item("New Linux tool blocks exploits before patching")), .digest)
        XCTAssertEqual(t(item("Proof-of-concept exploit code available for Ghostscript flaw")), .advisory)
        XCTAssertEqual(t(item("New macOS infostealer spreads via fake installers")), .campaign)
        XCTAssertEqual(t(item("Malicious npm packages poison builds")), .campaign)
        XCTAssertEqual(t(item("EU proposes new rules for app stores")), .digest)
        XCTAssertEqual(t(item("Ep 170: Zero-day brokers", source: "Darknet Diaries")), .digest)
    }

    func testHeadlineDecides() {
        func t(_ i: NewsItem) -> NewsTier { NewsClassifier.tier(i, kev: []) }
        XCTAssertEqual(t(item("Ransomware at the hypervisor layer", summary: "Attackers chain a vulnerability in ESXi.")), .campaign,
                       "the headline outranks a word in the summary")
        XCTAssertEqual(t(item("Malicious ScreenConnect deployments observed")), .campaign)
        XCTAssertEqual(t(item("Exchange for breakfast: Turla's Cereal tricks")), .campaign, "a named actor is a campaign")
        XCTAssertEqual(t(item("Lessons from cybersecurity Black Week", summary: "Patch every vulnerability.")), .digest)
        XCTAssertEqual(t(item("Weekly Update 531: Optimizely", source: "Troy Hunt", summary: "a breach")), .digest)
        XCTAssertEqual(t(item("Optimizely and the third parties", summary: "a breach of customer data")), .campaign,
                       "summary fallback still applies to plain headlines")
        XCTAssertEqual(News.text("Guest Diary &#x5b;1&#x5d; &amp;#91;2&amp;#93; &#128512;"), "Guest Diary [1] [2] 😀")
    }

    func testSyndicatedDuplicatesCluster() {
        let a = analyse([item("Operation ShadowCloud: backdoors in Asia", days: 2, source: "Securelist"),
                         item("Operation ShadowCloud: backdoors in Asia", days: 1.9, source: "Securelist")])
        XCTAssertEqual(a.units.count, 1)
    }

    func testNameMatchesDontCluster() {
        let prompt = ["app:Prompt@3.1@/Applications/Prompt 3.app"]
        let a = analyse([item("Prompt theft at AI firms", days: 2, relevance: .installed, packages: prompt),
                         item("More prompt theft", days: 1, relevance: .installed, packages: prompt)])
        XCTAssertEqual(a.units.filter(\.isCluster).count, 0)
    }

    func testDomains() {
        func d(_ t: String, _ summary: String = "") -> NewsDomain { NewsDomain.of(item(t, summary: summary)) }
        XCTAssertEqual(d("Drupal Warns of New Highly Critical Site Takeover Vulnerability"), .web)
        XCTAssertEqual(d("VMware vCenter Hit by Another Critical Auth Bypass Flaw"), .datacenter)
        XCTAssertEqual(d("Hackers Exploit Critical ScreenConnect Flaw to Hijack MSP Technician PCs"), .remote)
        XCTAssertEqual(d("Fortinet patches FortiGate SSL VPN flaw"), .network)
        XCTAssertEqual(d("13 Malicious NuGet Packages Deliver Malware"), .developer)
        XCTAssertEqual(d("Apple patches Safari zero-day"), .apple)
        XCTAssertEqual(d("Bazuka Android Malware Uses Fake Overlays"), .mobile)
        XCTAssertEqual(d("Attackers apply agentic AI to ransomware"), .general, "AI as the attacker's tool is not the AI domain")
        XCTAssertEqual(d("Critical flaw in popular MCP servers"), .ai)
        XCTAssertEqual(d("Who runs the ransomware group Qilin?", "A server in Ohio"), .datacenter, "summary words still count")
        XCTAssertTrue(NewsDomain.apple.nearThisMac); XCTAssertFalse(NewsDomain.datacenter.nearThisMac)

        let a = analyse([item("VMware vCenter zero-day exploited", days: 1), item("Drupal zero-day exploited", days: 0),
                         item("Chrome zero-day exploited", days: 2)])
        let g = a.sections()[1]
        XCTAssertTrue(g.groupsByDomain)
        XCTAssertEqual(g.byDomain.map(\.domain), [.desktop, .web, .datacenter], "nearest this Mac first")
        XCTAssertFalse(a.sections()[0].groupsByDomain)
    }

    func testProductsCluster() {
        let a = analyse([
            item("China-linked hackers exploit VMware vCenter zero-day", days: 3),
            item("VMware vCenter hit by another critical auth bypass flaw", days: 1, source: "Sophos Threat Research"),
        ])
        XCTAssertEqual(a.units.first(where: \.isCluster)?.key, .product("vCenter"))
    }

    func testSignals() {
        XCTAssertTrue(NewsClassifier.mentionsFix(item("Google patches Chrome zero-day")))
        XCTAssertFalse(NewsClassifier.mentionsFix(item("Unpatched routers hijacked")))
        XCTAssertFalse(NewsClassifier.mentionsFix(item("Patch Tuesday preview")), "Patch Tuesday alone is not a fix")
        XCTAssertEqual(NewsClassifier.keys(item("APT 28 and Salt Typhoon hit telcos", ["CVE-2026-9"])),
                       [.cve("CVE-2026-9"), .actor("APT28"), .actor("Salt Typhoon")])
        XCTAssertEqual(NewsClassifier.keys(item("Apple update", packages: ["macos:macOS@26.1@", "app:Safari@27@/Applications/Safari.app"])),
                       [.package("app:Safari@27@/Applications/Safari.app")], "macOS is too common to be a cluster key")
        XCTAssertEqual(NewsKey.package("go:gitleaks>golang.org/x/crypto@0.35.0@/bin/x").label, "golang.org/x/crypto")
    }

    // MARK: days

    func testDayBuckets() {
        let a = analyse([item("today"), item("edge", days: 29), item("old", days: 30.5), item("undated", days: nil)])
        XCTAssertEqual(a.days.count, 30)
        XCTAssertEqual(a.days.last, cal.startOfDay(for: now))
        XCTAssertEqual(a.days.first, cal.date(byAdding: .day, value: -29, to: cal.startOfDay(for: now)))
        let d = Dictionary(uniqueKeysWithValues: a.stories.map { ($0.item.title, $0.day) })
        XCTAssertEqual(d["today"]!, 29)
        XCTAssertEqual(d["edge"]!, 0)
        XCTAssertNil(d["old"]!)
        XCTAssertNil(d["undated"]!)
        XCTAssertEqual(a.metric(.volume)?.buckets[29], 1)
        XCTAssertEqual(a.metric(.volume)?.buckets[0], 1)
    }

    func testTrend() {
        var b = Array(repeating: 0, count: 30)
        XCTAssertEqual(NewsTrend.of(b), NewsTrend.none)
        b[29] = 2
        XCTAssertEqual(NewsTrend.of(b), .new, "0 → N is New, not a spike")
        b[16] = 1
        XCTAssertEqual(NewsTrend.of(b), .delta(1), "small numbers as counts")
        b[29] = 16
        XCTAssertEqual(NewsTrend.of(b), .delta(15), "1 → 16 is +15, not +1500%")
        b[29] = 9; b[16] = 6
        XCTAssertEqual(NewsTrend.of(b), .percent(50))
        b[29] = 3
        XCTAssertEqual(NewsTrend.of(b), .percent(-50))
        XCTAssertEqual(NewsTrend.of([1, 2]), NewsTrend.none)
    }

    // MARK: clusters

    func testClustersShareKeyWithinSevenDays() {
        let a = analyse([
            item("Ivanti flaw disclosed", ["CVE-2026-5000"], days: 6, source: "SANS ISC"),
            item("Ivanti flaw PoC published", ["CVE-2026-5000"], days: 3),
            item("Ivanti flaw follow-up", ["CVE-2026-5000"], days: 0, source: "Krebs on Security"),
            item("Same CVE weeks later", ["CVE-2026-6000"], days: 20),
            item("Same CVE again", ["CVE-2026-6000"], days: 5),
        ])
        let clusters = a.units.filter(\.isCluster)
        XCTAssertEqual(clusters.count, 1)
        XCTAssertEqual(clusters.first?.total, 3)
        XCTAssertEqual(clusters.first?.key, .cve("CVE-2026-5000"))
        XCTAssertEqual(clusters.first?.stories.first?.item.title, "Ivanti flaw follow-up", "newest first")
        XCTAssertEqual(clusters.first?.velocity, [1, 0, 0, 1, 0, 0, 1])
        XCTAssertEqual(clusters.first?.sources, 3)
        XCTAssertEqual(a.units.count, 3, "15 days apart stays separate")
    }

    func testChainingAndUndated() {
        let a = analyse([
            item("A", ["CVE-2026-1"], days: 12),
            item("B", ["CVE-2026-1"], days: 6),
            item("C", ["CVE-2026-1"], days: 0),
            item("D undated", ["CVE-2026-1"], days: nil),
        ])
        XCTAssertEqual(a.units.filter(\.isCluster).first?.total, 3, "links chain across a long-running story")
        XCTAssertTrue(a.units.contains { !$0.isCluster && $0.lead.item.title == "D undated" })
    }

    func testHotKeyDoesNotCluster() {
        let items = (0..<13).map { item("Story \($0)", ["CVE-2026-7"], days: Double($0) * 0.4) }
        XCTAssertEqual(analyse(items).units.filter(\.isCluster).count, 0)
    }

    func testClusterTakesBestTierAndNoDuplicates() {
        let chrome = "app:Google Chrome@142@/Applications/Google Chrome.app"
        let a = analyse([
            item("Chrome zero-day", ["CVE-2026-8"], days: 1, relevance: .affected, packages: [chrome]),
            item("Chrome bug writeup", ["CVE-2026-8"], days: 0),
            item("Unrelated malware campaign", days: 0),
            item("ThreatsDay: everything + 9 More Stories", ["CVE-2026-8"], days: 15),
        ], kev: ["CVE-2026-8"])
        let sections = a.sections()
        XCTAssertEqual(sections.map(\.section), NewsSection.allCases)
        let onMac = sections[0]
        XCTAssertEqual(onMac.units.count, 1)
        XCTAssertEqual(onMac.units[0].total, 2)
        XCTAssertEqual(onMac.units[0].stage, .exploited)
        let ids = sections.flatMap { $0.units.flatMap { $0.stories.map(\.id) } }
        XCTAssertEqual(ids.count, Set(ids).count, "every story appears once")
        XCTAssertEqual(ids.count, 4)
        XCTAssertEqual(sections[4].storyCount, 1, "the roundup is in the digest")
    }

    func testStages() {
        func stage(_ items: [NewsItem]) -> NewsStage? { analyse(items).units.first(where: \.isCluster)?.stage }
        XCTAssertEqual(stage([item("x one", ["CVE-1"], days: 1), item("x two", ["CVE-1"], days: 0.5)]), .new)
        XCTAssertEqual(stage([item("x one", ["CVE-1"], days: 5), item("x two", ["CVE-1"], days: 4)]), .ongoing)
        XCTAssertEqual(stage([item("x one", ["CVE-1"], days: 4), item("x two", ["CVE-1"], days: 1, source: "A"),
                              item("x three", ["CVE-1"], days: 0.5, source: "B")]), .escalating)
        XCTAssertEqual(stage([item("x one", ["CVE-1"], days: 4), item("x actively exploited", ["CVE-1"], days: 1)]), .exploited)
        let fix = analyse([item("x one", ["CVE-1"], days: 2), item("Vendor patches x", ["CVE-1"], days: 1)]).units.first(where: \.isCluster)
        XCTAssertEqual(fix?.fix, true)
    }

    func testRecurrence() {
        let a = analyse([
            item("Salt Typhoon first", days: 25),
            item("Salt Typhoon second", days: 15),
            item("Salt Typhoon now", days: 0),
            item("Salt Typhoon now, again", days: 0, source: "Krebs on Security"),
        ])
        let latest = a.units.first { $0.stories.contains { $0.item.title == "Salt Typhoon now" } }
        XCTAssertEqual(latest?.isCluster, true)
        XCTAssertEqual(latest?.recurrence?.key, .actor("Salt Typhoon"))
        XCTAssertEqual(latest?.recurrence?.ordinal, 3)
        XCTAssertEqual(latest?.recurrence?.text, "3rd mention · 30d")
        XCTAssertNil(a.units.first { $0.lead.item.title == "Salt Typhoon first" }?.recurrence, "the first mention isn't a recurrence")
        XCTAssertEqual(ordinalString(1), "1st"); XCTAssertEqual(ordinalString(12), "12th"); XCTAssertEqual(ordinalString(22), "22nd")
    }

    // MARK: filter and matrix

    func testFiltersAndMatrix() {
        let brew = "homebrew:openssh@10.0@/opt/homebrew/Cellar/openssh/10.0"
        let a = analyse([
            item("OpenSSH 10.1 fixes bug", days: 0, relevance: .installed, packages: [brew]),
            item("OpenSSH agent forwarding bug", days: 2, relevance: .installed, packages: [brew]),
            item("Exchange zero-day", days: 2),
            item("Policy piece", days: 2),
        ])
        XCTAssertEqual(a.count(.onThisMac), 2)
        XCTAssertEqual(a.count(.exploited), 1)
        XCTAssertEqual(a.count(.lane(.homebrew)), 2)
        XCTAssertEqual(a.count(.cell(day: 27, lane: .elsewhere)), 2)
        let cell = a.matrix[.homebrew]![29]
        XCTAssertEqual(cell.count, 1); XCTAssertEqual(cell.local, 1); XCTAssertEqual(cell.affected, 0)
        XCTAssertEqual(a.matrix[.elsewhere]![27].exploited, 1)
        let filtered = a.sections(filter: .day(27))
        XCTAssertEqual(filtered.map(\.storyCount), [1, 1, 0, 0, 1])
        XCTAssertEqual(a.sections(search: "exchange").map(\.storyCount).reduce(0, +), 1)
        XCTAssertEqual(a.metric(.onThisMac)?.total, 2)
        XCTAssertEqual(a.metric(.onThisMac)?.trend, .new)
    }

    func testFromReport() {
        var r = ScanReport(generated: now, posture: SystemPosture(), packages: [], findings: [], sources: [])
        r.news = [item("Fortinet bug", ["CVE-2026-42"])]
        r.timeline = [TimelineEntry(cve: "CVE-2026-42", added: "2026-11-20", vendor: "Fortinet", product: "FortiOS", name: "x",
                                    summary: "", ransomware: false, relevance: .elsewhere)]
        XCTAssertEqual(NewsAnalysis(report: r, now: now, calendar: cal).stories.first?.tier, .exploited)
        XCTAssertTrue(NewsAnalysis(report: ScanReport(generated: now, posture: SystemPosture(), packages: [], findings: [], sources: []),
                                   now: now, calendar: cal).units.isEmpty)
    }
}
