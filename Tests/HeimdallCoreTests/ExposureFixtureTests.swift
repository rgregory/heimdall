import XCTest
@testable import HeimdallCore

/// From the text ps, lsof and launchctl print to the order findings are shown in.
final class ExposureFixtureTests: XCTestCase {
    let ps = """
          1 /sbin/launchd
        412 /opt/homebrew/Cellar/redis/7.2.4/bin/redis-server
        533 /Applications/Demo.app/Contents/MacOS/Demo
        601 /usr/bin/login
    """
    let lsof = """
    p412
    n127.0.0.1:6379
    n[::1]:6379
    p533
    n*:49152
    """
    let launchctl = """
    PID\tStatus\tLabel
    412\t0\thomebrew.mxcl.redis
    -\t0\tcom.example.unrelated
    """

    func packages() -> [Package] {
        var redis = Package(ecosystem: .homebrew, name: "redis", version: "7.2.4", location: "/opt/homebrew/Cellar/redis/7.2.4")
        redis.bundleID = nil
        let idle = Package(ecosystem: .homebrew, name: "memcached", version: "1.6.0", location: "/opt/homebrew/Cellar/memcached/1.6.0")
        let app = Package(ecosystem: .app, name: "Demo", version: "4.1", location: "/Applications/Demo.app")
        var framework = Package(ecosystem: .app, name: "Sparkle", version: "2.6.4",
                                location: "/Applications/Demo.app/Contents/Frameworks/Sparkle.framework")
        framework.parent = "Demo"
        let python = Package(ecosystem: .pypi, name: "requests", version: "2.31.0")
        return [redis, idle, app, framework, python]
    }

    func testToolOutputDrivesExposureAndRanking() throws {
        var pkgs = packages()
        let agents = [(program: "/opt/homebrew/opt/redis/bin/redis-server", label: "homebrew.mxcl.redis")]
        let status = ExposureCollector.annotate(&pkgs,
            processes: ExposureCollector.parseProcesses(ps),
            ports: ExposureCollector.parsePorts(lsof),
            agents: agents, loaded: ExposureCollector.parseLabels(launchctl))
        XCTAssertEqual(status.state, .ok)
        let by = Dictionary(pkgs.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })

        let redis = try XCTUnwrap(by["redis"]?.exposure)
        XCTAssertTrue(redis.running)
        XCTAssertEqual(redis.ports, [6379], "two addresses, one port")
        XCTAssertTrue(redis.autostart, "matched through the Homebrew bin link")

        XCTAssertEqual(by["memcached"]?.exposure?.any, false)
        XCTAssertEqual(by["Demo"]?.exposure?.ports, [49152])
        XCTAssertEqual(by["Sparkle"]?.exposure?.running, true, "the framework inherits its host's answer")
        XCTAssertTrue(by["Sparkle"]?.exposure?.notes.first?.contains("reached through Demo") == true)
        XCTAssertNil(by["requests"]?.exposure, "a library inside an interpreter is unanswered, not idle")

        // Same advisory everywhere: what is listening ranks first, the idle copy last of the formulae.
        var v = Vulnerability(id: "CVE-2026-7"); v.severity = .high; v.cvss = 7.5
        let findings = pkgs.filter { $0.ecosystem != .pypi }.map { Finding(package: $0, vulns: [v], fixHint: "upgrade") }
            .sorted { $0.risk.score > $1.risk.score }
        XCTAssertEqual(findings.first?.package.name, "redis")
        let idleRisk = try XCTUnwrap(findings.first { $0.package.name == "memcached" }?.risk)
        XCTAssertTrue(idleRisk.factors.contains("not running when scanned"))
        XCTAssertLessThan(idleRisk.score, findings.first { $0.package.name == "Demo" }!.risk.score)
    }

    func testEmptyPsWarnsInsteadOfCallingEverythingIdle() {
        var pkgs = packages()
        let status = ExposureCollector.annotate(&pkgs, processes: [], ports: [:], agents: [], loaded: [])
        XCTAssertEqual(status.state, .warning)
        XCTAssertTrue(pkgs.allSatisfy { $0.exposure == nil })
    }
}

final class BrewServicesTests: XCTestCase {
    func testLoadedServiceLabelCountsAsAutostartWithoutAPlist() {
        var pkgs = [Package(ecosystem: .homebrew, name: "postgresql@16", version: "16.4", location: "/opt/homebrew/Cellar/postgresql@16/16.4")]
        _ = ExposureCollector.annotate(&pkgs, processes: [ExposureCollector.Proc(pid: 1, path: "/sbin/launchd")], ports: [:],
                                       agents: [], loaded: ["homebrew.mxcl.postgresql@16"])
        XCTAssertEqual(pkgs[0].exposure?.autostart, true)
        XCTAssertEqual(pkgs[0].exposure?.running, false)
    }
}
