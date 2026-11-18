import XCTest
@testable import HeimdallCore

// The four things a scan now says about a finding beyond the advisory itself: what is bundled
// inside what, whether it is reachable, how long it has been here, and whether anyone is ever
// going to fix it.

/// Package names come from metadata, so the check that gates every copyable command gets its
/// own tests.
final class PackageNameTests: XCTestCase {
    func testVersionedFormulaNamesSurviveValidation() {
        // Homebrew's versioned formulae are exactly the ones that reach end of life, so a command
        // naming them has to get past the name check — and nothing else should.
        var p = Package(ecosystem: .homebrew, name: "openssl@1.1", version: "1.1.1w")
        p.outdated = true
        XCTAssertEqual(Scanner.fixHint(p, []), "brew upgrade 'openssl@1.1'")
        XCTAssertTrue(Scanner.isPackageName("python@3.9"))
        XCTAssertTrue(Scanner.isPackageName("homebrew/core/node@18"))
        XCTAssertTrue(Scanner.isPackageName("@scope/pkg"))
        for bad in ["x; printf INJECTED", "--config=evil", "@", "openssl@", "@1.1", "name\ncommand", "$(id)", "openssl@1.1;id"] {
            XCTAssertFalse(Scanner.isPackageName(bad), bad)
        }
    }
}

final class BundledRuntimeTests: XCTestCase {
    func testVersionShapeDecidesWhatItIs() {
        // Chromium: four parts, major in the low hundreds.
        XCTAssertTrue(BundledCollector.isChromiumVersion("128.0.6613.186"))
        XCTAssertTrue(BundledCollector.isChromiumVersion("89.0.4389.90"))
        // Electron's own numbering, and CEF's two forms. 156.0.15.0 is CEF 156.0.15: it borrows
        // Chromium's major but not its build number, so comparing it against Chrome's ranges
        // would flag the whole 156 line.
        XCTAssertFalse(BundledCollector.isChromiumVersion("32.2.1"))
        XCTAssertFalse(BundledCollector.isChromiumVersion("156.0.15.0"))
        XCTAssertFalse(BundledCollector.isChromiumVersion("6533.2930.1341.ga6a7d1f"))
        XCTAssertFalse(BundledCollector.isChromiumVersion("2.6.4"))
        XCTAssertFalse(BundledCollector.isChromiumVersion(""))
    }

    /// A throwaway .app with the frameworks we care about inside it.
    func bundle(_ root: URL, frameworks: [String: String], java: String? = nil) throws -> String {
        let app = root.appendingPathComponent("Demo.app")
        for (dir, version) in frameworks {
            let res = app.appendingPathComponent("Contents/Frameworks/\(dir)/Resources", isDirectory: true)
            try FileManager.default.createDirectory(at: res, withIntermediateDirectories: true)
            let plist: [String: Any] = ["CFBundleShortVersionString": version, "CFBundleName": dir]
            let d = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            try d.write(to: res.appendingPathComponent("Info.plist"))
        }
        if let java {
            let home = app.appendingPathComponent("Contents/PlugIns/jre/Contents/Home", isDirectory: true)
            try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
            try "JAVA_VERSION=\"\(java)\"\nOS_ARCH=\"aarch64\"\n".write(to: home.appendingPathComponent("release"), atomically: true, encoding: .utf8)
        }
        return app.path
    }

    func testReadsNestedRuntimesAsChildrenOfTheApp() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let path = try bundle(root, frameworks: [
            "Electron Framework.framework": "128.0.6613.186",
            "Sparkle.framework": "2.6.4",
        ], java: "17.0.9")
        var host = Package(ecosystem: .app, name: "Demo", version: "4.1.0", location: path, source: "Info.plist")
        host.bundleID = "com.example.demo"

        let kids = BundledCollector.read(host)
        let byName = Dictionary(kids.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })

        // An Electron framework carrying a Chromium version is reported as Chromium, because that
        // is the only thing the number can honestly be compared against.
        let chromium = try XCTUnwrap(byName["Chromium"])
        XCTAssertEqual(chromium.version, "128.0.6613.186")
        XCTAssertEqual(chromium.bundleID, "org.chromium.engine")
        XCTAssertEqual(chromium.parent, "Demo")
        XCTAssertEqual(chromium.ownerApp, "Demo")

        XCTAssertEqual(byName["Sparkle"]?.version, "2.6.4")
        XCTAssertEqual(byName["Java"]?.version, "17.0.9")
        XCTAssertEqual(byName["Java"]?.bundleID, "com.oracle.java.jre")

        // Every synthetic id must resolve to a CPE, or nothing would ever be matched for it.
        let catalog = AppCatalog.builtIn
        for k in kids {
            guard let id = k.bundleID else { continue }
            XCTAssertNotNil(catalog.first { $0.matches(id) }, "no CPE mapping for \(id)")
        }
    }

    func testAdviceNamesTheHostAppNotTheFramework() {
        var host = Package(ecosystem: .app, name: "iTerm2", version: "3.7.6", location: "/Applications/iTerm.app", source: "Info.plist")
        host.outdated = false
        var kid = Package(ecosystem: .app, name: "Sparkle", version: "1.22.0", location: host.location + "/Contents/Frameworks/Sparkle.framework")
        kid.parent = "iTerm2"
        kid.ownerApp = "iTerm2"
        var v = Vulnerability(id: "CVE-2016-9892"); v.severity = .medium; v.fixed = ["1.26.0"]

        let hint = Scanner.fixHint(kid, [v])
        XCTAssertTrue(hint.contains("iTerm2"), hint)
        XCTAssertFalse(hint.hasPrefix("Update Sparkle"), "a framework has no menu to check")

        let steps = Scanner.fixSteps(kid, [v], packages: [host, kid])
        XCTAssertTrue(steps[0].hasPrefix("iTerm2 bundles Sparkle 1.22.0"), steps[0])
        XCTAssertTrue(steps.contains { $0.contains("already current") }, "say whose move it is")

        // Installed from a cask: the command is the host's cask, inherited by the framework.
        kid.cask = "iterm2"
        XCTAssertEqual(Scanner.fixHint(kid, [v]), "brew upgrade --cask 'iterm2' — it bundles Sparkle 1.22.0")

        // And when the host itself is behind, taking that update is the first step.
        var behind = host
        behind.outdated = true; behind.latest = "3.8.0"; behind.cask = "iterm2"
        let moving = Scanner.fixSteps(kid, [v], packages: [behind, kid])
        XCTAssertTrue(moving.contains { $0.contains("3.8.0 is out") }, moving.joined(separator: " | "))
    }

    func testElectronKeepsItsOwnVersionWhenThatIsWhatTheFrameworkSays() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let path = try bundle(root, frameworks: ["Electron Framework.framework": "32.2.1"])
        let host = Package(ecosystem: .app, name: "Demo", version: "1.0", location: path, source: "Info.plist")
        let kid = try XCTUnwrap(BundledCollector.read(host).first)
        XCTAssertEqual(kid.name, "Electron")
        XCTAssertEqual(kid.bundleID, "org.electronjs.Electron")
    }
}

final class ExposureTests: XCTestCase {
    func testParsesPs() {
        let out = """
          401 /System/Library/CoreServices/Dock.app/Contents/MacOS/Dock
         1234 /Applications/Visual Studio Code.app/Contents/MacOS/Electron
         9999 ???
        """
        let procs = ExposureCollector.parseProcesses(out)
        XCTAssertEqual(procs.count, 2, "a path that isn't a path is dropped")
        XCTAssertEqual(procs[1].pid, 1234)
        XCTAssertEqual(procs[1].path, "/Applications/Visual Studio Code.app/Contents/MacOS/Electron", "paths contain spaces")
    }

    func testParsesLsofFields() {
        let out = "p501\nn127.0.0.1:5432\nn*:8080\np777\nn[::1]:3000\n"
        let ports = ExposureCollector.parsePorts(out)
        XCTAssertEqual(ports[501], [5432, 8080])
        XCTAssertEqual(ports[777], [3000], "IPv6 addresses keep their port after the last colon")
    }

    func testParsesLaunchctlLabels() {
        let out = "PID\tStatus\tLabel\n-\t0\tcom.example.agent\n42\t0\tcom.example.helper\n"
        XCTAssertEqual(ExposureCollector.parseLabels(out), ["com.example.agent", "com.example.helper"])
    }

    func testOwnership() {
        let app = Package(ecosystem: .app, name: "Demo", version: "1", location: "/Applications/Demo.app")
        XCTAssertTrue(ExposureCollector.owns(app, "/Applications/Demo.app/Contents/MacOS/Demo"))
        XCTAssertFalse(ExposureCollector.owns(app, "/Applications/Demo Helper.app/Contents/MacOS/x"))

        // Homebrew runs its programs from <prefix>/bin, not from the keg.
        let brew = Package(ecosystem: .homebrew, name: "nginx", version: "1.27.3", location: "/opt/homebrew/Cellar/nginx/1.27.3")
        XCTAssertTrue(ExposureCollector.owns(brew, "/opt/homebrew/bin/nginx"))
        XCTAssertTrue(ExposureCollector.owns(brew, "/opt/homebrew/Cellar/nginx/1.27.3/bin/nginx"))
        XCTAssertFalse(ExposureCollector.owns(brew, "/opt/homebrew/bin/nginx-helper"))
    }

    func testListeningPackagePicksUpItsPort() {
        let p = Package(ecosystem: .homebrew, name: "nginx", version: "1.27.3", location: "/opt/homebrew/Cellar/nginx/1.27.3")
        let procs = [ExposureCollector.Proc(pid: 501, path: "/opt/homebrew/bin/nginx")]
        let e = try! XCTUnwrap(ExposureCollector.exposure(p, paths: procs.map(\.path), processes: procs,
                                                          ports: [501: [8080]], agents: [], loaded: []))
        XCTAssertTrue(e.running)
        XCTAssertEqual(e.ports, [8080])
        XCTAssertTrue(e.summary.contains("listening on 8080"))
    }

    func testLaunchdAgentCountsAsAutostart() {
        let p = Package(ecosystem: .app, name: "Demo", version: "1", location: "/Applications/Demo.app")
        let e = try! XCTUnwrap(ExposureCollector.exposure(p, paths: [], processes: [], ports: [:],
                                                          agents: [(program: "/Applications/Demo.app/Contents/MacOS/Agent", label: "com.example.demo")],
                                                          loaded: []))
        XCTAssertTrue(e.autostart)
        XCTAssertFalse(e.running)
    }

    func testUnanswerableKindsStayUnanswered() {
        // A library inside an interpreter cannot be seen running, and "idle" would be a lie.
        let lib = Package(ecosystem: .pypi, name: "requests", version: "2.25.0", location: "/x/site-packages/requests")
        XCTAssertNil(ExposureCollector.exposure(lib, paths: ["/opt/homebrew/bin/python3"], processes: [], ports: [:], agents: [], loaded: []))
    }

    func testExtensionFollowsItsBrowser() {
        var ext = Package(ecosystem: .browserExtension, name: "Some Extension", version: "1.2")
        ext.browser = "Chrome"
        let running = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
        XCTAssertEqual(ExposureCollector.exposure(ext, paths: running, processes: [], ports: [:], agents: [], loaded: [])?.running, true)
        XCTAssertEqual(ExposureCollector.exposure(ext, paths: ["/Applications/Firefox.app/Contents/MacOS/firefox"],
                                                  processes: [], ports: [:], agents: [], loaded: [])?.running, false)
    }
}

final class MaintenanceTests: XCTestCase {
    func testBrewDeprecationIsRead() {
        let j: [String: Any] = [
            "formulae": [["name": "openssl@1.1", "installed": [["version": "1.1.1w"]], "linked_keg": "1.1.1w",
                          "deprecated": true, "deprecation_date": "2023-09-11", "deprecation_reason": "unmaintained",
                          "deprecation_replacement": "openssl@3", "outdated": false]],
            "casks": [["token": "old-app", "installed": "1.0", "artifacts": [["app": ["Old.app"]]],
                       "disabled": true, "disable_reason": "repo_archived", "outdated": false]],
        ]
        let pkgs = BrewCollector.parse(j, prefix: "/opt/homebrew")
        let formula = try! XCTUnwrap(pkgs.first { $0.name == "openssl@1.1" }.flatMap(\.maintenance))
        XCTAssertEqual(formula.state, .deprecated)
        XCTAssertTrue(formula.reason.contains("nobody is maintaining it upstream"))
        XCTAssertEqual(formula.replacement, "openssl@3")
        XCTAssertFalse(formula.terminal, "deprecated still installs and may still get a version")

        let cask = try! XCTUnwrap(pkgs.first { $0.name == "old-app" }.flatMap(\.maintenance))
        XCTAssertEqual(cask.state, .disabled)
        XCTAssertTrue(cask.terminal)
        XCTAssertTrue(cask.reason.contains("repository is archived"))
    }

    func testEndOfLifeOnlyCountsAfterTheDate() {
        var pkgs = [
            Package(ecosystem: .homebrew, name: "node@18", version: "18.20.4"),
            Package(ecosystem: .homebrew, name: "node@24", version: "24.1.0"),
            Package(ecosystem: .homebrew, name: "python@3.9", version: "3.9.19"),
        ]
        // A day before Node 18 went out of support, nothing is said about it.
        MaintenanceCheck.local(&pkgs, now: MaintenanceCheck.day.date(from: "2025-04-01")!)
        XCTAssertNil(pkgs[0].maintenance)
        MaintenanceCheck.local(&pkgs, now: MaintenanceCheck.day.date(from: "2026-11-18")!)
        XCTAssertEqual(pkgs[0].maintenance?.state, .endOfLife)
        XCTAssertTrue(pkgs[0].maintenance?.terminal == true)
        XCTAssertNil(pkgs[1].maintenance, "a supported release is left alone")
        XCTAssertEqual(pkgs[2].maintenance?.state, .endOfLife)
    }

    func testBrewsOwnWordWins() {
        var pkgs = [Package(ecosystem: .homebrew, name: "python@3.9", version: "3.9.19")]
        pkgs[0].maintenance = Maintenance(state: .disabled, reason: "Homebrew has disabled this formula.", source: "brew info")
        MaintenanceCheck.local(&pkgs, now: Date())
        XCTAssertEqual(pkgs[0].maintenance?.source, "brew info")
    }

    func testAdviceIsRemovalNotUpgrade() {
        var p = Package(ecosystem: .homebrew, name: "openssl@1.1", version: "1.1.1w")
        p.maintenance = Maintenance(state: .endOfLife, reason: "OpenSSL 1.1.1 stopped getting security fixes on 11 September 2023.",
                                    source: "release calendar", replacement: "openssl@3")
        var v = Vulnerability(id: "CVE-2024-1"); v.fixed = []
        XCTAssertTrue(Scanner.fixHint(p, [v]).hasPrefix("brew uninstall 'openssl@1.1'"))
        let steps = Scanner.fixSteps(p, [v], packages: [p])
        XCTAssertTrue(steps.contains { $0.contains("will not be fixed") })
        XCTAssertTrue(steps.contains { $0.hasPrefix("brew uninstall") })

        // Inside an app there is nothing to uninstall, and saying otherwise would be wrong.
        var bundled = Package(ecosystem: .app, name: "Chromium", version: "89.0.4389.90", location: "/Applications/Demo.app/Contents/Frameworks/Electron Framework.framework")
        bundled.parent = "Demo"
        bundled.maintenance = Maintenance(state: .endOfLife, reason: "Chromium 89 is years past support.", source: "release calendar")
        let inside = Scanner.fixSteps(bundled, [v], packages: [bundled])
        XCTAssertTrue(inside.contains { $0.contains("bundled inside Demo") })
        XCTAssertFalse(inside.contains { $0.hasPrefix("brew uninstall") })
    }

    func testPointerOutOfADeprecationNote() {
        XCTAssertEqual(MaintenanceCheck.pointer(in: "This package is deprecated, use @scope/next instead"), "@scope/next")
        XCTAssertNil(MaintenanceCheck.pointer(in: "no longer supported"))
    }
}

final class RiskContextTests: XCTestCase {
    func finding(_ build: (inout Package) -> Void = { _ in }) -> Finding {
        var p = Package(ecosystem: .homebrew, name: "demo", version: "1.0", location: "/opt/homebrew/Cellar/demo/1.0")
        build(&p)
        var v = Vulnerability(id: "CVE-2026-1"); v.severity = .high; v.cvss = 8.1; v.fixed = ["1.1"]
        return Finding(package: p, vulns: [v], fixHint: "brew upgrade 'demo'")
    }

    func testListeningOutranksIdle() {
        let idle = finding { p in p.exposure = Exposure() }
        var listeningPkg = Exposure(); listeningPkg.running = true; listeningPkg.ports = [5432]
        let listening = finding { p in p.exposure = listeningPkg }
        XCTAssertGreaterThan(listening.risk.score, idle.risk.score)
        XCTAssertTrue(listening.risk.factors.contains("listening on 5432"))
        XCTAssertTrue(idle.risk.factors.contains("not running when scanned"))
    }

    func testUnknownExposureIsNeutral() {
        let unknown = finding()
        XCTAssertFalse(unknown.risk.factors.contains("not running when scanned"), "no answer is not a 'no'")
    }

    func testAgePushesUp() {
        var old = finding()
        old.firstSeen = Date().addingTimeInterval(-30 * 86400)
        let fresh = finding()
        XCTAssertEqual(old.ageDays, 30)
        XCTAssertGreaterThan(old.risk.score, fresh.risk.score)
        XCTAssertTrue(old.risk.factors.contains("open for 30 days"))
    }

    func testAbandonedRanksAsWorkRatherThanAsWaiting() {
        var stuck = finding()
        stuck.awaitingRelease = true
        stuck.fixHint = "No fixed release yet — demo 1.0 is the newest available."
        XCTAssertTrue(stuck.risk.blocked)

        var dead = stuck
        dead.package.maintenance = Maintenance(state: .withdrawn, reason: "Yanked after it shipped.", source: "PyPI")
        XCTAssertFalse(dead.risk.blocked, "there is nothing to wait for, so it isn't blocked")
        XCTAssertTrue(dead.risk.abandoned)
        XCTAssertGreaterThan(dead.risk.score, stuck.risk.score)
        XCTAssertTrue(dead.risk.factors.contains { $0.contains("no fix is ever coming") })
    }

    func testBundledStillRanksBelowTheSameFlawYouRun() {
        var inside = finding { p in p.parent = "Demo"; p.ecosystem = .app }
        inside.fixHint = "Update Demo from its menu (Check for Updates…)"
        let own = finding()
        XCTAssertLessThan(inside.risk.score, own.risk.score)
    }
}

final class HistoryTests: XCTestCase {
    func testFirstSeenIsTheOldestSightingAcrossTheAdvisories() {
        var p = Package(ecosystem: .npm, name: "left-pad", version: "1.0.0")
        p.parent = nil
        var a = Vulnerability(id: "CVE-2026-1"), b = Vulnerability(id: "CVE-2026-2")
        a.severity = .high; b.severity = .low
        var r = ScanReport(generated: Date(), posture: SystemPosture(), packages: [p],
                           findings: [Finding(package: p, vulns: [a, b])], sources: [])
        let old = Date().addingTimeInterval(-10 * 86400)
        History.apply(&r, [History.key(p, a): Date().addingTimeInterval(-86400), History.key(p, b): old])
        XCTAssertEqual(r.findings[0].firstSeen, old)
        XCTAssertEqual(r.findings[0].ageDays, 10)
    }

    func testKeyIgnoresTheVersion() {
        var one = Package(ecosystem: .pypi, name: "requests", version: "2.25.0")
        var two = one; two.version = "2.26.0"
        let v = Vulnerability(id: "CVE-2026-9")
        XCTAssertEqual(History.key(one, v), History.key(two, v), "a patch release that doesn't fix it is the same open problem")
        one.parent = "pipx"
        XCTAssertNotEqual(History.key(one, v), History.key(two, v))
    }
}

final class ContextExportTests: XCTestCase {
    func testCSVCarriesTheNewColumns() {
        var p = Package(ecosystem: .homebrew, name: "demo", version: "1.0")
        var e = Exposure(); e.running = true; e.ports = [8080]
        p.exposure = e
        p.maintenance = Maintenance(state: .endOfLife, reason: "past support", source: "release calendar")
        var v = Vulnerability(id: "CVE-2026-1"); v.severity = .high
        var f = Finding(package: p, vulns: [v], fixHint: "brew uninstall 'demo'")
        f.firstSeen = Date().addingTimeInterval(-9 * 86400)
        let csv = ReportExport.csv(ScanReport(generated: Date(), posture: SystemPosture(), packages: [p], findings: [f], sources: []))
        let header = csv.split(whereSeparator: \.isNewline)[0]
        for column in ["running", "listening", "autostart", "first_seen", "age_days", "maintenance", "maintenance_reason"] {
            XCTAssertTrue(header.contains(column), "missing \(column)")
        }
        XCTAssertTrue(csv.contains("endOfLife"))
        XCTAssertTrue(csv.contains(",9,"))
    }
}
