import XCTest
@testable import HeimdallCore

final class CoverageBreakdownTests: XCTestCase {
    func testBuiltInBrewVulnsTreatsAbsentFormulaeAsChecked() throws {
        let json = """
        {"findings":[{"formula":"openssl@3","version":"3.0.13","vulnerabilities":[{"id":"CVE-2024-1","published":"2024-05-01T00:00:00Z","fixed_versions":["3.0.14"]}],"patched":[]}],
         "skipped_formulae":["homebrew/core/foo"],"checked":120,"complete":false,
         "outdated_without_sbom":["bar"],"unscanned_formulae":{"baz":"untrusted keg"}}
        """
        let d = Data(json.utf8)
        let c = try XCTUnwrap(BrewVulnsParser.coverage(d))
        XCTAssertEqual(c.checked, 120)
        XCTAssertEqual(c.unscanned["foo"], "no source version")
        XCTAssertEqual(c.unscanned["bar"], "outdated, no SBOM")
        XCTAssertEqual(c.unscanned["baz"], "untrusted keg")
        XCTAssertNil(c.unscanned["jq"])
        let v = try XCTUnwrap(BrewVulnsParser.parse(d)["openssl@3"]?.first)
        XCTAssertNotNil(v.published)
        XCTAssertEqual(v.fixed, ["3.0.14"])
    }

    func testOldGemOutputHasNoCoverage() {
        XCTAssertNil(BrewVulnsParser.coverage(Data(#"[{"formula":"x","vulnerabilities":[]}]"#.utf8)))
    }
}

final class BrewRevisionTests: XCTestCase {
    func testRevisionsCompare() {
        XCTAssertEqual(Version.compareBrew("1.11.1_7", "1.11.1_7"), 0)
        XCTAssertGreaterThan(Version.compareBrew("1.11.1_7", "1.11.1"), 0)
        XCTAssertGreaterThan(Version.compareBrew("1.11.1_10", "1.11.1_9"), 0)
        XCTAssertEqual(Version.compareBrew("1.11.1_7-1", "1.11.1_7"), 0)
        XCTAssertLessThan(Version.compareBrew("1.11.1_7", "1.11.2"), 0)
    }

    func testPickPrefersHighestRevision() {
        XCTAssertEqual(Bottles.pick(["1.11.0", "1.11.1", "1.11.1_6", "1.11.1_7", "1.11.1_10", "1.11.1_7-1"]), "1.11.1_10")
    }
}

final class UnbottledFixTests: XCTestCase {
    func testUpstreamFixNotYetInHomebrewIsNotFixableNow() {
        var p = Package(ecosystem: .homebrew, name: "openssl@4", version: "4.1.0")
        var v = Vulnerability(id: "CVE-2026-9"); v.fixed = ["4.1.1"]
        XCTAssertTrue(Scanner.awaitingRelease(p, [v]), "brew has nothing newer, so brew upgrade is a no-op")
        XCTAssertTrue(Scanner.fixHint(p, [v]).hasPrefix("Fixed upstream in 4.1.1, but Homebrew hasn't shipped it yet"))
        p.outdated = true
        XCTAssertFalse(Scanner.awaitingRelease(p, [v]))
        XCTAssertEqual(Scanner.fixHint(p, [v]), "brew upgrade 'openssl@4'")
    }
}
