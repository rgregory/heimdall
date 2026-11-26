import XCTest
@testable import HeimdallCore

final class CycloneDXTests: XCTestCase {
    func testComponentsVulnerabilitiesAndSignals() throws {
        let py = Package(ecosystem: .pypi, name: "Requests_Toolbelt", version: "1.0.0")
        let scoped = Package(ecosystem: .npm, name: "@babel/core", version: "7.24.0-rc.1")
        let app = Package(ecosystem: .app, name: "Demo", version: "4.1")
        var v = Vulnerability(id: "GHSA-xxxx"); v.aliases = ["CVE-2026-1"]; v.severity = .critical
        v.cvss = 9.8; v.vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"; v.epss = 0.42; v.fixed = ["1.0.1"]
        v.kev = KEVEntry(cveID: "CVE-2026-1", vendorProject: "demo", product: "demo", vulnerabilityName: "",
                         dateAdded: "2026-11-18", shortDescription: "", requiredAction: "", dueDate: "", knownRansomwareCampaignUse: "Known")
        // The same advisory on two packages becomes one entry affecting both.
        let r = ScanReport(generated: Date(timeIntervalSince1970: 0), posture: SystemPosture(), packages: [py, scoped, app],
                           findings: [Finding(package: py, vulns: [v]), Finding(package: scoped, vulns: [v])], sources: [])
        let data = ReportExport.cycloneDX(r, serial: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!)
        let doc = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(doc["bomFormat"] as? String, "CycloneDX")
        XCTAssertEqual(doc["specVersion"] as? String, "1.5")
        XCTAssertEqual(doc["serialNumber"] as? String, "urn:uuid:00000000-0000-0000-0000-000000000001")

        let comps = try XCTUnwrap(doc["components"] as? [[String: Any]])
        XCTAssertEqual(comps.count, 3)
        XCTAssertEqual(comps[0]["purl"] as? String, "pkg:pypi/requests-toolbelt@1.0.0", "PyPI names are normalized")
        XCTAssertEqual(comps[1]["purl"] as? String, "pkg:npm/%40babel/core@7.24.0-rc.1")
        XCTAssertEqual(comps[1]["group"] as? String, "@babel")
        XCTAssertNil(comps[2]["purl"], "apps have no registered purl type")
        XCTAssertEqual(comps[2]["type"] as? String, "application")

        let vulns = try XCTUnwrap(doc["vulnerabilities"] as? [[String: Any]])
        XCTAssertEqual(vulns.count, 1)
        let e = vulns[0]
        XCTAssertEqual(e["id"] as? String, "CVE-2026-1")
        XCTAssertEqual((e["affects"] as? [[String: String]])?.compactMap { $0["ref"] }, ["pkg-0", "pkg-1"])
        let rating = try XCTUnwrap((e["ratings"] as? [[String: Any]])?.first)
        XCTAssertEqual(rating["method"] as? String, "CVSSv31")
        XCTAssertEqual(rating["severity"] as? String, "critical")
        let props = Dictionary(((e["properties"] as? [[String: String]]) ?? []).map { ($0["name"]!, $0["value"]!) }, uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(props["heimdall:kev"], "CISA KEV")
        XCTAssertEqual(props["heimdall:ransomware"], "known")
        XCTAssertEqual(props["heimdall:epss"], "0.42000")
    }
}
