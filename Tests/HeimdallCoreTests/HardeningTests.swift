import XCTest
@testable import HeimdallCore

/// Heimdall's own answers must not depend on whatever a user-writable folder puts first on PATH.
final class ToolResolutionTests: XCTestCase {
    func testSystemToolsComeFromFixedLocationsOnly() {
        XCTAssertEqual(Shell.systemTools["ps"], "/bin/ps")
        XCTAssertEqual(Shell.systemTools["lsof"], "/usr/sbin/lsof")
        XCTAssertEqual(Shell.systemTools["launchctl"], "/bin/launchctl")
        XCTAssertNil(Shell.systemTool("brew"), "only the fixed table is consulted, never PATH")
    }

    func testFakePsEarlierOnPathIsIgnored() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let fake = dir.appendingPathComponent("ps")
        try "#!/bin/sh\necho 1 /nothing/running\n".write(to: fake, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fake.path)

        // A PATH search would find the fake one first...
        XCTAssertEqual(Shell.which("ps", in: dir.path + ":/bin"), fake.path)
        // ...but the collector's lookup never searches.
        if let ps = Shell.systemTool("ps") { XCTAssertEqual(ps, "/bin/ps") }
    }

    func testBuiltPathPutsFixedLocationsFirstAndNeedsNoShell() {
        let p = Shell.buildPath(home: "/Users/u", extra: "~/bin: /opt/tools/bin :relative")
        let parts = p.split(separator: ":").map(String.init)
        XCTAssertEqual(Array(parts.prefix(4)), ["/usr/bin", "/bin", "/usr/sbin", "/sbin"])
        XCTAssertLessThan(parts.firstIndex(of: "/opt/homebrew/bin")!, parts.firstIndex(of: "/Users/u/.local/bin")!)
        XCTAssertEqual(Array(parts.suffix(2)), ["/Users/u/bin", "/opt/tools/bin"], "extras go last; relative entries are dropped")
        XCTAssertFalse(parts.contains("relative"))
        XCTAssertEqual(parts.count, Set(parts).count)
    }
}

final class EcosystemVersionTests: XCTestCase {
    func testPEP440Ordering() {
        let ordered = ["1.0.dev1", "1.0a1", "1.0a2.dev1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0+local.1", "1.0.post1.dev1", "1.0.post1", "1.0.1", "1!0.1"]
        for (a, b) in zip(ordered, ordered.dropFirst()) {
            XCTAssertEqual(Version.compare(a, b, in: .pypi), -1, "\(a) < \(b)")
            XCTAssertEqual(Version.compare(b, a, in: .pypi), 1, "\(b) > \(a)")
        }
        XCTAssertEqual(Version.compare("1.0", "1.0.0", in: .pypi), 0)
        XCTAssertEqual(Version.compare("1.0-1", "1.0.post1", in: .pypi), 0, "implicit post release")
        XCTAssertEqual(Version.compare("1.0.0RC1", "1.0.0rc1", in: .pypi), 0)
    }

    func testPostReleaseIsNotOlderThanTheFix() {
        // The bug: a post release of the fixed version read as older, so it stayed "vulnerable".
        XCTAssertFalse(Version.less("2.31.0.post1", "2.31.0", in: .pypi))
        XCTAssertFalse(Version.less("9.8p1", "9.8"), "loose order: OpenSSH-style p1 is after 9.8")
        XCTAssertTrue(Version.less("1.0b1", "1.0"), "loose order: betas still precede the release")
    }

    func testSemVerOrdering() {
        let ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "v1.1.0"]
        for (a, b) in zip(ordered, ordered.dropFirst()) {
            XCTAssertEqual(Version.compare(a, b, in: .npm), -1, "\(a) < \(b)")
        }
        XCTAssertEqual(Version.compare("1.0.0+build.5", "1.0.0", in: .crates), 0, "build metadata is ignored")
        XCTAssertEqual(Version.compare("v2.0.0+incompatible", "2.0.0", in: .go), 0)
        XCTAssertEqual(Version.compare("1.0.0-beta.11", "1.0.0-beta.2", in: .npm), 1, "numeric identifiers compare as numbers")
    }

    func testUnparseableFallsBackToLooseOrder() {
        XCTAssertEqual(Version.compare("weird-thing", "weird-thing", in: .npm), 0)
        XCTAssertEqual(Version.compare("2024.1", "2023.9", osvEcosystem: "GIT"), 1)
    }
}
