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
