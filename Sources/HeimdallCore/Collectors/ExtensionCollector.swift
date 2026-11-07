import Foundation

/// Browser extensions in your own browser profiles: Chromium-family `manifest.json` files and
/// Firefox's `extensions.json`. Readable as you; nothing is opened in the browser.
public enum ExtensionCollector {
    static let chromium: [(String, String)] = [
        ("Chrome", "~/Library/Application Support/Google/Chrome"),
        ("Brave", "~/Library/Application Support/BraveSoftware/Brave-Browser"),
        ("Edge", "~/Library/Application Support/Microsoft Edge"),
        ("Vivaldi", "~/Library/Application Support/Vivaldi"),
        ("Arc", "~/Library/Application Support/Arc/User Data"),
        ("Chromium", "~/Library/Application Support/Chromium"),
        ("Opera", "~/Library/Application Support/com.operasoftware.Opera"),
    ]

    public static func collect() -> CollectorOutput {
        var out = CollectorOutput()
        var seen = Set<String>()
        for (browser, root) in chromium {
            let base = Paths.expand(root)
            guard FS.isDir(base) else { continue }
            // Profiles: Default, Profile 1…, or (Opera) the root itself.
            let profiles = FS.list(base).filter { $0 == "Default" || $0.hasPrefix("Profile ") }.map { base + "/" + $0 } + [base]
            for prof in profiles {
                let extDir = prof + "/Extensions"
                for id in FS.list(extDir) where id.count == 32 {
                    // Newest installed version folder.
                    guard let ver = FS.list(extDir + "/" + id).filter({ !$0.hasPrefix(".") }).max(by: { Version.less($0, $1) }) else { continue }
                    let dir = "\(extDir)/\(id)/\(ver)"
                    guard let m = jsonObject(FS.read(dir + "/manifest.json")) as? [String: Any] else { continue }
                    let name = localized(m["name"] as? String ?? id, dir: dir, defaultLocale: m["default_locale"] as? String)
                    guard seen.insert("\(browser)|\(id)").inserted else { continue }
                    var p = Package(ecosystem: .browserExtension, name: name, version: (m["version"] as? String) ?? ver.replacingOccurrences(of: "_0", with: ""),
                                    location: dir, source: "\(browser) extension")
                    p.bundleID = id
                    p.browser = browser
                    out.packages.append(p)
                }
            }
        }
        // Firefox
        for prof in FS.glob("~/Library/Application Support/Firefox/Profiles/*") {
            guard let j = jsonObject(FS.read(prof + "/extensions.json")) as? [String: Any] else { continue }
            for a in j["addons"] as? [[String: Any]] ?? [] {
                guard let id = a["id"] as? String, (a["type"] as? String ?? "extension") == "extension",
                      let loc = a["location"] as? String, loc == "app-profile" else { continue }   // skip built-ins
                let name = ((a["defaultLocale"] as? [String: Any])?["name"] as? String) ?? id
                guard seen.insert("Firefox|\(id)").inserted else { continue }
                var p = Package(ecosystem: .browserExtension, name: name, version: a["version"] as? String ?? "", location: prof, source: "Firefox add-on")
                p.bundleID = id
                p.browser = "Firefox"
                out.packages.append(p)
            }
        }
        out.status.append(SourceStatus(name: "Browser extensions", state: out.packages.isEmpty ? .skipped : .ok,
                                       detail: out.packages.isEmpty ? "no Chromium-family or Firefox profiles found" : "Chrome, Brave, Edge, Vivaldi, Arc, Opera and Firefox profiles",
                                       count: out.packages.count, updated: Date()))
        return out
    }

    /// Resolve "__MSG_appName__" from _locales.
    static func localized(_ name: String, dir: String, defaultLocale: String?) -> String {
        guard name.hasPrefix("__MSG_"), name.hasSuffix("__") else { return name }
        let key = String(name.dropFirst(6).dropLast(2)).lowercased()
        for loc in [defaultLocale, "en", "en_US"].compactMap({ $0 }) {
            guard let j = jsonObject(FS.read("\(dir)/_locales/\(loc)/messages.json")) as? [String: Any] else { continue }
            for (k, v) in j where k.lowercased() == key {
                if let m = (v as? [String: Any])?["message"] as? String, !m.isEmpty { return m }
            }
        }
        return name
    }
}

/// A community-maintained list of Chrome Web Store IDs removed for malware.
public enum MaliciousExtensions {
    public static let url = "https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/Malicious-Extensions.csv"

    public static func load(offline: Bool) async -> (Set<String>, SourceStatus) {
        let cache = DiskCache("feeds")
        var data = cache.data("malicious-extensions.csv", maxAge: offline ? nil : 86400)
        var note = "cached"
        if data == nil && !offline {
            do { let d = try await HTTP.get(url); cache.store("malicious-extensions.csv", d); data = d; note = "downloaded" }
            catch { data = cache.data("malicious-extensions.csv"); note = "download failed (\(error))" }
        }
        let text = data.map { String(decoding: $0, as: UTF8.self) } ?? ""
        let ids = Set(text.allMatches(#"\b[a-p]{32}\b"#).map { $0[0] })
        return (ids, SourceStatus(name: "Malicious extension list", state: ids.isEmpty ? .warning : .ok,
                                  detail: ids.isEmpty ? "unavailable (\(note))" : "\(ids.count) known-bad Chrome extension IDs (\(note))", count: ids.count, updated: Date()))
    }
}
