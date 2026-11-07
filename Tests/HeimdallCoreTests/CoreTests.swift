import XCTest
@testable import HeimdallCore

final class VersionTests: XCTestCase {
    func testOrdering() {
        XCTAssertLessThan(Version.compare("1.2.3", "1.2.10"), 0)
        XCTAssertEqual(Version.compare("1.2", "1.2.0"), 0)
        XCTAssertGreaterThan(Version.compare("124.0.6367.201", "124.0.6367.91"), 0)
        XCTAssertLessThan(Version.compare("2.0rc1", "2.0"), 0)
        XCTAssertLessThan(Version.compare("1.0.0-beta.2", "1.0.0"), 0)
        XCTAssertEqual(Version.compare("v1.4.0", "1.4.0"), 0)
        XCTAssertGreaterThan(Version.compare("15.1", "15.0.1"), 0)
        XCTAssertEqual(Version.stripBrewRevision("3.2.1_1"), "3.2.1")
    }
}

final class CVSSTests: XCTestCase {
    func testScores() {
        XCTAssertEqual(CVSS.baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"), 9.6)
        XCTAssertEqual(CVSS.baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        XCTAssertEqual(CVSS.baseScore("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 5.5)
        XCTAssertEqual(CVSS.baseScore("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0)
        XCTAssertNil(CVSS.baseScore("CVSS:4.0/AV:N"))
    }
}

final class NVDTests: XCTestCase {
    func cve(_ configs: [NVDCve.Config]) -> NVDCve {
        NVDCve(id: "CVE-1", published: nil, summary: "", score: 9, severity: nil, vector: nil, kevAdded: nil, configs: configs, references: [])
    }
    func m(_ c: String, vee: String? = nil, vsi: String? = nil, vuln: Bool = true) -> NVDCve.Match {
        NVDCve.Match(vulnerable: vuln, criteria: c, vsi: vsi, vse: nil, vei: nil, vee: vee)
    }

    func testRange() {
        let c = cve([.init(op: "OR", nodes: [.init(op: "OR", negate: false, matches: [m("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", vee: "124.0.6367.201")])])])
        XCTAssertEqual(NVDClient.evaluate(c, part: "a", vendor: "google", product: "chrome", version: "124.0.6367.91"), .affected)
        XCTAssertEqual(NVDClient.evaluate(c, part: "a", vendor: "google", product: "chrome", version: "124.0.6367.201"), .notAffected)
    }

    func testRunningOnWindowsOnly() {
        let c = cve([.init(op: "AND", nodes: [
            .init(op: "OR", negate: false, matches: [m("cpe:2.3:a:zoom:meetings:*:*:*:*:*:*:*:*", vee: "6.0")]),
            .init(op: "OR", negate: false, matches: [m("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", vuln: false)]),
        ])])
        XCTAssertEqual(NVDClient.evaluate(c, part: "a", vendor: "zoom", product: "meetings", version: "5.0"), .notAffected)
        let mac = cve([.init(op: "AND", nodes: [
            .init(op: "OR", negate: false, matches: [m("cpe:2.3:a:zoom:meetings:*:*:*:*:*:*:*:*", vee: "6.0")]),
            .init(op: "OR", negate: false, matches: [m("cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*", vuln: false)]),
        ])])
        XCTAssertEqual(NVDClient.evaluate(mac, part: "a", vendor: "zoom", product: "meetings", version: "5.0"), .affected)
    }

    func testTargetSoftware() {
        let c = cve([.init(op: "OR", nodes: [.init(op: "OR", negate: false, matches: [m("cpe:2.3:a:google:chrome:*:*:*:*:*:android:*:*", vee: "200")])])])
        XCTAssertEqual(NVDClient.evaluate(c, part: "a", vendor: "google", product: "chrome", version: "100"), .notAffected)
    }

    func testExactAndUnbounded() {
        let exact = cve([.init(op: "OR", nodes: [.init(op: "OR", negate: false, matches: [m("cpe:2.3:o:apple:macos:15.1:*:*:*:*:*:*:*")])])])
        XCTAssertEqual(NVDClient.evaluate(exact, part: "o", vendor: "apple", product: "macos", version: "15.1"), .affected)
        XCTAssertEqual(NVDClient.evaluate(exact, part: "o", vendor: "apple", product: "macos", version: "15.2"), .notAffected)
        let star = cve([.init(op: "OR", nodes: [.init(op: "OR", negate: false, matches: [m("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*")])])])
        XCTAssertEqual(NVDClient.evaluate(star, part: "a", vendor: "x", product: "y", version: "1"), .affectedUnbounded)
    }

    func testCPEVersion() {
        XCTAssertEqual(NVDClient.cpeVersion("6.2.5 (43380)"), "6.2.5")
        XCTAssertEqual(NVDClient.cpeVersion("131.0.6778.86"), "131.0.6778.86")
    }
}

final class ParserTests: XCTestCase {
    func testKEV() {
        let j = #"{"catalogVersion":"2026.11.05","dateReleased":"2026-11-05","vulnerabilities":[{"cveID":"CVE-2024-4671","vendorProject":"Google","product":"Chromium Visuals","vulnerabilityName":"Google Chromium Visuals Use-After-Free","dateAdded":"2024-05-13","shortDescription":"x","requiredAction":"Apply","dueDate":"2024-06-03","knownRansomwareCampaignUse":"Unknown"}]}"#
        let c = KEVCatalog.parse(Data(j.utf8))
        XCTAssertEqual(c?.version, "2026.11.05")
        XCTAssertEqual(c?["CVE-2024-4671"]?.product, "Chromium Visuals")
    }

    func testOSVVuln() {
        let j: [String: Any] = [
            "id": "GHSA-xxxx", "aliases": ["CVE-2023-1234"], "summary": "Bad thing",
            "severity": [["type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]],
            "affected": [["package": ["name": "Requests", "ecosystem": "PyPI"], "ranges": [["type": "ECOSYSTEM", "events": [["introduced": "0"], ["fixed": "2.31.0"]]]]]],
        ]
        let v = OSVClient.vulnerability(j, ecosystem: "PyPI", package: "requests")
        XCTAssertEqual(v.headlineID, "CVE-2023-1234")
        XCTAssertEqual(v.cvss, 9.8)
        XCTAssertEqual(v.severity, .critical)
        XCTAssertEqual(v.fixed, ["2.31.0"])
    }

    func testBrewVulns() {
        let j = #"{"formulae":[{"name":"curl","version":"8.5.0","vulnerabilities":[{"id":"CVE-2024-2398","severity":"medium","fixed_version":"8.7.1"}]}]}"#
        let r = BrewVulnsParser.parse(Data(j.utf8))
        XCTAssertEqual(r["curl"]?.first?.id, "CVE-2024-2398")
        XCTAssertEqual(r["curl"]?.first?.fixed, ["8.7.1"])
    }

    func testAppleReleases() {
        let html = """
        <table><tr><th>Name</th><th>Available for</th><th>Release date</th></tr>
        <tr><td><a href="/en-us/121564">macOS Sequoia 15.1</a></td><td>macOS Sequoia</td><td>28 Oct 2024</td></tr>
        <tr><td><a href="/en-us/121570">macOS Sequoia 15.2</a></td><td>macOS Sequoia</td><td>11 Dec 2024</td></tr>
        <tr><td>Safari 18.1</td><td>macOS</td><td>28 Oct 2024</td></tr></table>
        """
        let r = AppleReleases.parse(html)
        XCTAssertEqual(r.count, 3)
        XCTAssertEqual(r[0].version, "15.1")
        XCTAssertEqual(r[0].link, "https://support.apple.com/en-us/121564")
        XCTAssertFalse(r[2].hasCVEs)
        let b = AppleReleases.behind(r, product: "macOS", installed: "15.1")
        XCTAssertEqual(b.latest, "15.2")
        XCTAssertEqual(b.newer.map(\.version), ["15.2"])
    }

    func testGoBuildInfo() {
        var d = Data(repeating: 0, count: 64)
        d += GoBuildInfo.magic
        d += Data([8, 2]) + Data(repeating: 0, count: 16)
        func vs(_ s: String) -> Data { Data([UInt8(s.utf8.count)]) + Data(s.utf8) }
        let mod = "0123456789abcdef" + "path\tgithub.com/x/tool\nmod\tgithub.com/x/tool\tv1.2.3\th1:abc=\ndep\tgolang.org/x/net\tv0.17.0\th1:def=\n" + "0123456789abcdef"
        d += vs("go1.21.4") + Data([UInt8(mod.utf8.count & 0x7f | 0x80), UInt8(mod.utf8.count >> 7)]) + Data(mod.utf8)
        let info = GoBuildInfo.parse(d)
        XCTAssertEqual(info?.goVersion, "go1.21.4")
        XCTAssertEqual(info?.mainVersion, "v1.2.3")
        XCTAssertEqual(info?.deps.first?.path, "golang.org/x/net")
        let pkgs = info!.packages(binary: "tool", path: "/x/tool")
        XCTAssertEqual(pkgs.map(\.name), ["stdlib", "github.com/x/tool", "golang.org/x/net"])
        XCTAssertEqual(pkgs[0].version, "1.21.4")
        XCTAssertEqual(pkgs[2].version, "0.17.0")
    }

    func testBrewParse() {
        let j: [String: Any] = [
            "formulae": [["name": "jq", "installed": [["version": "1.7"], ["version": "1.7.1"]], "linked_keg": "1.7.1",
                          "urls": ["stable": ["url": "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-1.7.1.tar.gz"]], "outdated": false]],
            "casks": [["token": "firefox", "installed": "144.0", "artifacts": [["app": ["Firefox.app"]]], "outdated": true]],
        ]
        let p = BrewCollector.parse(j, prefix: "/opt/homebrew")
        XCTAssertEqual(p[0].version, "1.7.1")
        XCTAssertEqual(p[0].repo, "https://github.com/jqlang/jq")
        XCTAssertEqual(p[1].bundleID, "Firefox.app")
        XCTAssertTrue(p[1].outdated)
    }

    func testDedupe() {
        var a = Vulnerability(id: "GHSA-1"); a.aliases = ["CVE-2024-1"]; a.severity = .medium; a.fixed = ["1.2"]
        var b = Vulnerability(id: "PYSEC-9"); b.aliases = ["CVE-2024-1"]; b.cvss = 8.1; b.severity = .high; b.fixed = ["1.2.1"]
        let d = Scanner.dedupe([a, b])
        XCTAssertEqual(d.count, 1)
        XCTAssertEqual(d[0].severity, .high)
        XCTAssertEqual(d[0].cvss, 8.1)
        XCTAssertTrue(d[0].aliases.contains("PYSEC-9"))
    }

    func testCSV() {
        var v = Vulnerability(id: "CVE-1"); v.summary = "has, comma"
        let r = ScanReport(generated: Date(), posture: SystemPosture(), packages: [], findings: [Finding(package: Package(ecosystem: .npm, name: "x", version: "1"), vulns: [v])], sources: [])
        XCTAssertTrue(ReportExport.csv(r).contains("\"has, comma\""))
    }
}

final class SourceParserTests: XCTestCase {
    func testAppleNotes() {
        let html = """
        <h2>macOS 15.2</h2><h3 class="gb-header">Kernel</h3><p class="gb-paragraph">Impact: An app may gain root</p>
        <p>CVE-2024-44308: someone</p><h3 class="gb-header">WebKit</h3><p class="gb-paragraph">Impact: Crash</p><p>CVE-2024-44309</p>
        """
        let e = AppleNotes.parse(html)
        XCTAssertEqual(Set(e.map(\.cve)), ["CVE-2024-44308", "CVE-2024-44309"])
        XCTAssertEqual(e.first { $0.cve == "CVE-2024-44308" }?.component, "Kernel")
    }

    func testChromeReleases() {
        let xml = """
        <entry><published>2026-10-29T10:00:00.000-07:00</published><title type='text'>Stable Channel Update for Desktop</title>
        <content type='html'>&lt;p&gt;Chrome 156.0.8078.79/.80 for Windows, Mac&lt;/p&gt; [$7000][123] High CVE-2026-1111: Use after free in V8. Reported by x
        [TBD][456] Critical CVE-2026-2222: Type Confusion in Blink. Reported</content>
        <link rel='alternate' type='text/html' href='https://chromereleases.googleblog.com/2026/10/x.html' title='x'/></entry>
        """
        let posts = ChromeReleases.parse(xml)
        XCTAssertEqual(posts.first?.version, "156.0.8078.79")
        XCTAssertEqual(posts.first?.cves.count, 2)
        let open = ChromeReleases.open(posts, installed: "155.0.1.1")
        XCTAssertEqual(open.first { $0.id == "CVE-2026-2222" }?.severity, .critical)
        XCTAssertTrue(ChromeReleases.open(posts, installed: "156.0.8078.80").isEmpty)
    }

    func testAppcast() {
        let xml = """
        <rss><channel><item><title>3.5.1</title><enclosure sparkle:shortVersionString="3.5.1" sparkle:version="351"/></item>
        <item><sparkle:channel>beta</sparkle:channel><enclosure sparkle:shortVersionString="3.6.0beta1"/></item>
        <item><sparkle:shortVersionString>3.5.10</sparkle:shortVersionString></item></channel></rss>
        """
        XCTAssertEqual(UpdateChecks.latestInAppcast(xml), "3.5.10")
        var p = Package(ecosystem: .app, name: "iTerm", version: "3.4.0")
        XCTAssertTrue(UpdateChecks.set(&p, "3.5.10", "Sparkle feed"))
        XCTAssertTrue(p.outdated)
    }

    func testMSRC() {
        let j: [String: Any] = [
            "ProductTree": ["FullProductName": [["ProductID": "1", "Value": "Microsoft Office 365 for Mac"], ["ProductID": "2", "Value": "Windows 11"]]],
            "Vulnerability": [[
                "CVE": "CVE-2026-1", "Title": ["Value": "Microsoft Excel Remote Code Execution Vulnerability"],
                "Remediations": [["ProductID": ["1"], "FixedBuild": "16.114.26101123"]],
                "Threats": [["Type": 1, "Description": ["Value": "Publicly Disclosed:No;Exploited:Yes"]]],
                "CVSSScoreSets": [["BaseScore": 7.8]],
            ], [
                "CVE": "CVE-2026-2", "Title": ["Value": "Windows Kernel"], "Remediations": [["ProductID": ["2"], "FixedBuild": "10.0.1"]],
            ]],
        ]
        let e = MSRC.reduce(j, month: "2026-Oct")
        XCTAssertEqual(e.map(\.cve), ["CVE-2026-1"])
        var excel = Package(ecosystem: .app, name: "Microsoft Excel", version: "16.100"); excel.bundleID = "com.microsoft.Excel"; excel.build = "16.100.25081015"
        var word = Package(ecosystem: .app, name: "Microsoft Word", version: "16.100"); word.bundleID = "com.microsoft.Word"; word.build = "16.100.25081015"
        let v = MSRC.open(e, for: excel)
        XCTAssertEqual(v.first?.kev?.source, "MSRC")
        XCTAssertTrue(MSRC.open(e, for: word).isEmpty, "Excel-only advisory shouldn't land on Word")
        excel.build = "16.115.1"
        XCTAssertTrue(MSRC.open(e, for: excel).isEmpty)
    }

    func testCVERecordPath() {
        XCTAssertEqual(CVERecords.path("CVE-2024-44308"), "2024/44xxx/CVE-2024-44308.json")
        XCTAssertEqual(CVERecords.path("CVE-2024-0012"), "2024/0xxx/CVE-2024-0012.json")
    }

    func testOptionsDecodeOld() throws {
        let old = #"{"apps":false,"homebrew":true,"useBrewVulns":true,"nvd":true,"epss":true,"offline":false,"includeUnbounded":false,"extraAppRoots":[],"languages":{"python":true,"npm":true,"npmNested":false,"cargo":true,"gems":true,"go":true,"goInHomebrew":false,"extraPythonRoots":[],"extraGoRoots":[]}}"#
        let o = try JSONDecoder().decode(ScanOptions.self, from: Data(old.utf8))
        XCTAssertFalse(o.apps)
        XCTAssertTrue(o.vendorFeeds)
    }
}

final class FixHintTests: XCTestCase {
    func testAwaitingUpstreamRelease() {
        var p = Package(ecosystem: .homebrew, name: "libssh2", version: "1.11.1")
        var v = Vulnerability(id: "OSV-2025-433"); v.fixed = ["commit 1a2b3c4d5e"]
        XCTAssertTrue(Scanner.awaitingRelease(p, [v]))
        XCTAssertTrue(Scanner.fixHint(p, [v]).hasPrefix("No fixed release yet"))
        p.outdated = true   // Homebrew has something newer: upgrading is worth it
        XCTAssertEqual(Scanner.fixHint(p, [v]), "brew upgrade 'libssh2'")
        var py = Package(ecosystem: .pypi, name: "requests", version: "2.25.0")
        var w = Vulnerability(id: "GHSA-x"); w.fixed = ["2.31.0"]
        XCTAssertFalse(Scanner.awaitingRelease(py, [w]))
        py.version = "2.32.0"; w.fixed = []
        XCTAssertFalse(Scanner.awaitingRelease(py, [w]), "no fix info at all: don't claim anything")
    }
}
