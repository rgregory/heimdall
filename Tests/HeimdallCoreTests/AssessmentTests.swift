import XCTest
@testable import HeimdallCore

final class AssessmentTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    func package(_ version: String = "1.0", location: String = "/env/site-packages") -> Package {
        var p = Package(ecosystem: .pypi, name: "demo", version: version, location: location)
        p.coverage = PackageCoverage(.checked, "OSV.dev: completed")
        return p
    }
    func report(_ p: Package?, findings: [Finding] = []) -> ScanReport {
        var r = ScanReport(generated: now, posture: SystemPosture(), packages: p.map { [$0] } ?? [], findings: findings,
                           sources: [SourceStatus(name: "Python", state: .ok, detail: "Inventory complete", count: p == nil ? 0 : 1)])
        r.scanOptions = ScanOptions()
        return r
    }
    func vulnerability(exploited: Bool = false, id: String = "CVE-2026-1") -> Vulnerability {
        var v = Vulnerability(id: id)
        if exploited {
            v.kev = KEVEntry(cveID: id, vendorProject: "demo", product: "demo", vulnerabilityName: "",
                             dateAdded: "2026-11-18", shortDescription: "", requiredAction: "", dueDate: "", knownRansomwareCampaignUse: "")
        }
        return v
    }
    func testOnlyAnUpgradeWithCompletedChecksConfirmsAFix() {
        let p = package(), v = vulnerability()
        let f = Finding(package: p, vulns: [v])
        let before = report(p, findings: [f])
        let changes = Changes(current: report(package("1.1")), previous: before)
        XCTAssertEqual(changes.resolved.count, 1)
        XCTAssertEqual(changes.outcome(f, v), .fixed)
        let unchanged = Changes(current: report(p), previous: before)
        XCTAssertTrue(unchanged.resolved.isEmpty)
        XCTAssertEqual(unchanged.outcome(f, v), .unconfirmed)
    }
    func testLookupFailureDoesNotResolveAFinding() {
        let p = package(), v = vulnerability()
        let f = Finding(package: p, vulns: [v])
        var updated = package("1.1")
        updated.coverage = PackageCoverage(.unavailable, "Refresh failed")
        let changes = Changes(current: report(updated), previous: report(p, findings: [f]))
        XCTAssertEqual(changes.outcome(f, v), .unavailable)
        XCTAssertTrue(changes.resolved.isEmpty)
        XCTAssertEqual(changes.unverified.count, 1)
    }
    func testChangedOrSkippedCollectorDoesNotProveRemoval() {
        let before = report(package())
        var current = report(nil)
        current.scanOptions?.languages.python = false
        XCTAssertEqual(RemediationOutcome.assess(package(), in: current, previous: before), .notChecked)
        current = report(nil)
        XCTAssertEqual(RemediationOutcome.assess(package(), in: current, previous: before), .removed)
        current.sources = [SourceStatus(name: "Python", state: .skipped, detail: "Not available")]
        XCTAssertEqual(RemediationOutcome.assess(package(), in: current, previous: before), .notChecked)
    }
    func testPartialReportDoesNotPublishChanges() {
        let f = Finding(package: package(), vulns: [vulnerability()])
        var current = report(nil); current.partial = true
        XCTAssertTrue(Changes(current: current, previous: report(package(), findings: [f])).isEmpty)
    }
    func testWarningAndOfflineCacheDoNotConfirmFixes() {
        let before = report(package())
        var current = report(package("1.1"))
        current.sources.append(SourceStatus(name: "OSV.dev", state: .warning, detail: "Stale fallback"))
        XCTAssertEqual(RemediationOutcome.assess(package(), in: current, previous: before), .unavailable)
        current = report(package("1.1"))
        current.packages[0].coverage = PackageCoverage(.cached, "Offline")
        XCTAssertEqual(RemediationOutcome.assess(package(), in: current, previous: before), .unavailable)
    }
    func testSeparateInstallationsAreComparedIndependently() {
        let f = Finding(package: package(), vulns: [vulnerability()])
        let other = package("1.1", location: "/different/site-packages")
        let changes = Changes(current: report(other, findings: [Finding(package: other, vulns: [vulnerability()])]),
                              previous: report(package(), findings: [f]))
        XCTAssertEqual(changes.appeared.count, 1)
        XCTAssertEqual(changes.outcome(f, vulnerability()), .removed)
    }
    func testInstallationIdentitySurvivesBrewAndExtensionUpdates() {
        let a = Package(ecosystem: .homebrew, name: "demo", version: "1.0", location: "/opt/homebrew/Cellar/demo/1.0_2")
        let b = Package(ecosystem: .homebrew, name: "demo", version: "1.1", location: "/opt/homebrew/Cellar/demo/1.1")
        XCTAssertEqual(a.installationKey, b.installationKey)
        var ext = Package(ecosystem: .browserExtension, name: "Demo", version: "1", location: "/Profile/Extensions/abc/1_0")
        ext.bundleID = "abc"
        var updated = ext; updated.version = "2"; updated.location = "/Profile/Extensions/abc/2_0"
        XCTAssertEqual(ext.installationKey, updated.installationKey)
    }
    func testExceptionExpiryInstallationAndAdvisoryScope() {
        let exception = FindingException(package: package(), vulnerability: vulnerability(), scope: .advisory,
            reason: "Waiting for maintenance", expires: now.addingTimeInterval(60), exploited: false)
        XCTAssertTrue(exception.applies(to: package(), vulnerability: vulnerability(), now: now))
        XCTAssertFalse(exception.applies(to: package(), vulnerability: vulnerability(), now: now.addingTimeInterval(60)))
        XCTAssertFalse(exception.applies(to: package(location: "/other"), vulnerability: vulnerability(), now: now))
        XCTAssertFalse(exception.applies(to: package(), vulnerability: vulnerability(id: "CVE-2026-2"), now: now))
    }
    func testVersionAndInstallationExceptionsBehaveDifferentlyOnUpgrade() {
        for scope in [FindingException.Scope.version, .installation] {
            let exception = FindingException(package: package(), vulnerability: nil, scope: scope,
                reason: "Deferred", expires: now.addingTimeInterval(60), exploited: false)
            XCTAssertTrue(exception.applies(to: package(), vulnerability: vulnerability(), now: now))
            XCTAssertEqual(exception.applies(to: package("1.1"), vulnerability: vulnerability(), now: now), scope == .installation)
            XCTAssertFalse(exception.applies(to: package(), vulnerability: vulnerability(exploited: true), now: now))
        }
    }
    func testAcceptingOneExploitedAdvisoryDoesNotHideAnother() {
        let exception = FindingException(package: package(), vulnerability: vulnerability(exploited: true), scope: .installation,
            reason: "Waiting for a fix", expires: now.addingTimeInterval(60), exploited: true)
        XCTAssertTrue(exception.applies(to: package(), vulnerability: vulnerability(exploited: true), now: now))
        XCTAssertFalse(exception.applies(to: package(), vulnerability: vulnerability(exploited: true, id: "CVE-2026-2"), now: now))
    }
    func testLegacyReportsRemainReadableWithoutClaimingCoverage() throws {
        var old = report(package()); old.scanOptions = nil; old.packages[0].coverage = nil
        let decoded = try JSONCoding.decoder.decode(ScanReport.self, from: JSONCoding.encoder.encode(old))
        XCTAssertNil(decoded.scanOptions)
        XCTAssertNil(decoded.packages[0].coverage)
        XCTAssertEqual(decoded.coverageGaps.count, 1)
        XCTAssertEqual(RemediationOutcome.assess(package(), in: decoded, previous: old), .notChecked)
    }
    func testExceptionsAndCoverageRoundTrip() throws {
        let exception = FindingException(package: package(), vulnerability: vulnerability(), scope: .advisory,
            reason: "Deferred", expires: now.addingTimeInterval(60), exploited: false)
        XCTAssertEqual(try JSONDecoder().decode(FindingException.self, from: JSONEncoder().encode(exception)), exception)
        let decoded = try JSONCoding.decoder.decode(ScanReport.self, from: JSONCoding.encoder.encode(report(package())))
        XCTAssertTrue(decoded.coverageGaps.isEmpty)
        XCTAssertEqual(decoded.packages[0].coverage?.state, .checked)
    }
    func testBestEffortGitTagMatchCannotVerifyAnUpgrade() {
        var installed = package("1.1")
        installed.coverage?.supportsUpgradeVerification = false
        XCTAssertEqual(RemediationOutcome.assess(package(), in: report(installed), previous: report(package())), .unconfirmed)
    }

    func testMissingNVDCacheIsNotSuccessfulCoverage() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("heimdall-coverage-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let client = NVDClient(offline: true, cache: DiskCache(directory: dir)) { _, _ in
            XCTFail("Offline lookup must not make a request")
            return Data()
        }
        let scanner = Scanner(options: ScanOptions())
        let entry = AppCPE(bundleID: "demo", cpe: ["demo:demo"])
        let result = await scanner.nvdMatch(package(), entry, nvd: client, kev: KEVCatalog(), posture: SystemPosture())
        XCTAssertTrue(result.failed)
        XCTAssertTrue(result.vulns.isEmpty)
    }

}
