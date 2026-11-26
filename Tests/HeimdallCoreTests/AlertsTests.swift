import XCTest
@testable import HeimdallCore

final class AlertsTests: XCTestCase {
    func kev(_ id: String, ransomware: Bool = false) -> Vulnerability {
        var v = Vulnerability(id: id); v.severity = .high
        v.kev = KEVEntry(cveID: id, vendorProject: "demo", product: "demo", vulnerabilityName: "", dateAdded: "2026-11-18",
                         shortDescription: "", requiredAction: "", dueDate: "", knownRansomwareCampaignUse: ransomware ? "Known" : "")
        return v
    }
    func report(_ findings: [Finding]) -> ScanReport {
        ScanReport(generated: Date(), posture: SystemPosture(), packages: findings.map(\.package), findings: findings, sources: [])
    }

    func testOnlyNewUndeferredExploitedFindingsAlert() {
        let p = Package(ecosystem: .homebrew, name: "demo", version: "1.0")
        let q = Package(ecosystem: .npm, name: "other", version: "2.0")
        let old = Finding(package: p, vulns: [kev("CVE-2026-1")])
        var plain = Vulnerability(id: "CVE-2026-9"); plain.severity = .critical
        let current = report([Finding(package: p, vulns: [kev("CVE-2026-1"), kev("CVE-2026-2", ransomware: true), plain]),
                              Finding(package: q, vulns: [kev("CVE-2026-3")])])
        let deferred = FindingException(package: q, vulnerability: kev("CVE-2026-3"), scope: .advisory, reason: "test",
                                        expires: Date().addingTimeInterval(86400), exploited: true)

        let items = Alerts.newExploited(current: current, previous: report([old]), exceptions: [deferred])
        XCTAssertEqual(items.map(\.advisory), ["CVE-2026-2"], "already known, not exploited and deferred findings stay quiet")
        let m = try! XCTUnwrap(Alerts.message(items))
        XCTAssertEqual(m.title, "Exploited: demo")
        XCTAssertTrue(m.body.contains("ransomware"))

        var partial = current; partial.partial = true
        XCTAssertTrue(Alerts.newExploited(current: partial, previous: nil, exceptions: []).isEmpty)
        XCTAssertNil(Alerts.message([]))
    }

    func testReleaseCheck() throws {
        let json = #"{"tag_name":"v1.2.0","html_url":"https://github.com/rgregory/heimdall/releases/tag/v1.2.0","draft":false,"prerelease":false}"#
        let r = try XCTUnwrap(ReleaseCheck.parse(Data(json.utf8)))
        XCTAssertEqual(r.version, "1.2.0")
        XCTAssertEqual(ReleaseCheck.newer(r, than: "1.0.0"), r)
        XCTAssertNil(ReleaseCheck.newer(r, than: "1.2.0"))
        XCTAssertNil(ReleaseCheck.newer(r, than: "1.10.0"))
        XCTAssertNil(ReleaseCheck.parse(Data(#"{"tag_name":"v2.0.0-beta","html_url":"x","prerelease":true}"#.utf8)))
        XCTAssertNil(ReleaseCheck.parse(Data(#"{"message":"Not Found"}"#.utf8)))
    }
}
