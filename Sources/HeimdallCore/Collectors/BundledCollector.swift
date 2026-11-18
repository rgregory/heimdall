import Foundation

/// Runtimes that ship inside an application bundle. An app's own version number says nothing
/// about the engine inside it: an Electron app can call itself current while carrying a browser
/// engine from two years ago, and nothing in its `Contents/Info.plist` gives that away. Each
/// nested framework's own Info.plist does, so these are read from there and reported as children
/// of the app that carries them — the thing you update is always the host app, never the
/// framework inside it.
public enum BundledCollector {
    public static func collect(apps: [Package]) -> CollectorOutput {
        var out = CollectorOutput()
        // Apple's own bundles are updated with macOS and covered by the system checks; Safari
        // and Xcode are the two it still makes sense to look inside.
        for app in apps where app.ecosystem == .app && app.parent == nil && !app.location.isEmpty && !AppCollector.isApple(app) {
            out.packages += read(app)
        }
        let hosts = Set(out.packages.compactMap(\.parent)).count
        let detail = out.packages.isEmpty
            ? "no Electron, Chromium, Sparkle, Python or Java runtime inside the installed apps"
            : "Info.plist of frameworks inside \(hosts) app\(hosts == 1 ? "" : "s")"
        out.status.append(SourceStatus(name: "Bundled runtimes", state: .ok, detail: detail,
                                       count: out.packages.count, updated: Date()))
        return out
    }

    struct Known: Sendable {
        /// Directory name inside Contents/Frameworks.
        let dir: String
        let name: String
        /// Synthetic bundle id; AppCatalog maps it to a CPE.
        let id: String
    }

    /// Only frameworks whose version can be compared against something published. The rest of
    /// Contents/Frameworks is left alone: a list of frameworks nothing can be matched against is
    /// noise, and Inventory is long enough already.
    static let known: [Known] = [
        Known(dir: "Electron Framework.framework", name: "Electron", id: "org.electronjs.Electron"),
        Known(dir: "Chromium Embedded Framework.framework", name: "Chromium Embedded Framework", id: "org.chromium.cef"),
        Known(dir: "Sparkle.framework", name: "Sparkle", id: "org.sparkle-project.Sparkle"),
        Known(dir: "Python.framework", name: "Python", id: "org.python.python"),
    ]

    /// The engine inside Electron and CEF is Chromium, but only sometimes is the version in the
    /// framework a Chromium version. A real one is four numeric parts with a major in the low
    /// hundreds *and* a build number in the thousands: 128.0.6613.186. CEF's own numbering copies
    /// Chromium's major and then uses its own small numbers — 156.0.15.0 is CEF 156.0.15, whose
    /// engine is really 156.0.8011.something — and Electron's is two or three parts. Only the
    /// first form can be compared against Chrome's published ranges; comparing a CEF version
    /// against them would mark every advisory in that major line as affecting this Mac.
    static func isChromiumVersion(_ v: String) -> Bool {
        let parts = v.split(separator: ".")
        guard parts.count == 4, parts.allSatisfy({ $0.allSatisfy(\.isNumber) }),
              let major = Int(parts[0]), let build = Int(parts[2]) else { return false }
        return (50...399).contains(major) && build >= 1000
    }

    static func read(_ app: Package) -> [Package] {
        var out: [Package] = []
        let frameworks = app.location + "/Contents/Frameworks"
        for k in known {
            let path = frameworks + "/" + k.dir
            guard FS.isDir(path), let version = frameworkVersion(path) else { continue }
            var name = k.name, id = k.id
            if k.id == "org.electronjs.Electron" || k.id == "org.chromium.cef" {
                if isChromiumVersion(version) {
                    name = "Chromium"
                    id = "org.chromium.engine"
                } else if k.id == "org.chromium.cef" {
                    // CEF's own numbering matches no published advisory, so it is inventory only.
                    id = ""
                }
            }
            let via = name == k.name ? k.dir : "\(k.dir) (\(name) \(version))"
            out.append(child(app, name: name, version: version, id: id, path: path, source: "Info.plist of \(via)"))
        }
        if let java = javaRuntime(app.location) {
            out.append(child(app, name: "Java", version: java.version, id: "com.oracle.java.jre",
                             path: java.home, source: "release file of the bundled Java runtime"))
        }
        return out
    }

    /// Framework layouts differ: a flat bundle keeps one Info.plist under Resources, a versioned
    /// one keeps a plist per version, and Python's version is the directory name whether or not
    /// anything inside agrees.
    static func frameworkVersion(_ path: String) -> String? {
        for p in ["/Resources/Info.plist", "/Versions/Current/Resources/Info.plist", "/Versions/A/Resources/Info.plist"] {
            if let v = plistVersion(path + p) { return v }
        }
        let versions = FS.list(path + "/Versions").filter { $0 != "Current" && $0.first?.isNumber == true }
        guard let newest = versions.max(by: { Version.less($0, $1) }) else { return nil }
        return plistVersion(path + "/Versions/\(newest)/Resources/Info.plist") ?? newest
    }

    static func plistVersion(_ p: String) -> String? {
        guard let d = FS.read(p),
              let pl = (try? PropertyListSerialization.propertyList(from: d, format: nil)) as? [String: Any] else { return nil }
        let short = (pl["CFBundleShortVersionString"] as? String)?.trimmed ?? ""
        let build = (pl["CFBundleVersion"] as? String)?.trimmed ?? ""
        let v = short.isEmpty ? build : short
        return v.isEmpty ? nil : v
    }

    /// A bundled Java runtime announces its version in a `release` file at the root of its home.
    static let javaHomes = ["Contents/PlugIns/jre/Contents/Home", "Contents/jre/Contents/Home",
                            "Contents/Resources/jre/Contents/Home", "Contents/Resources/app/jre/Contents/Home",
                            "Contents/Frameworks/jre/Contents/Home", "Contents/PlugIns/jdk/Contents/Home"]

    static func javaRuntime(_ bundle: String) -> (version: String, home: String)? {
        for h in javaHomes {
            let home = bundle + "/" + h
            guard let t = FS.text(home + "/release"), let m = t.firstMatch("JAVA_VERSION=\"([^\"]+)\"") else { continue }
            return (m[1], home)
        }
        return nil
    }

    static func child(_ app: Package, name: String, version: String, id: String, path: String, source: String) -> Package {
        var p = Package(ecosystem: .app, name: name, version: version, location: path, source: source)
        p.parent = app.name
        p.ownerApp = app.name
        if !id.isEmpty { p.bundleID = id }
        p.modified = FS.mtime(path)
        return p
    }
}
