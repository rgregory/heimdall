import Foundation

/// Application bundles the user can see: /Applications (two levels deep, for vendor folders)
/// and ~/Applications. Reads each bundle's Info.plist; nothing is launched.
public enum AppCollector {
    public static func collect(extraRoots: [String] = []) -> CollectorOutput {
        var out = CollectorOutput()
        let roots = ["/Applications", "/Applications/Utilities", "~/Applications"] + extraRoots
        var seen = Set<String>()
        for root in roots.map(Paths.expand) where FS.isDir(root) {
            for e in FS.list(root) {
                let p = root + "/" + e
                if e.hasSuffix(".app") { if let a = read(p), seen.insert(FS.resolve(p)).inserted { out.packages.append(a) } }
                else if FS.isDir(p) && !e.hasPrefix(".") && e != "Utilities" {
                    for e2 in FS.list(p) where e2.hasSuffix(".app") {
                        let q = p + "/" + e2
                        if let a = read(q), seen.insert(FS.resolve(q)).inserted { out.packages.append(a) }
                    }
                }
            }
        }
        // Safari ships with macOS but is versioned on its own.
        for p in ["/Applications/Safari.app", "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app"] where seen.insert(FS.resolve(p)).inserted {
            if let a = read(p) { out.packages.append(a) }
        }
        out.status.append(SourceStatus(name: "Applications", state: .ok, detail: "Info.plist of bundles in /Applications and ~/Applications", count: out.packages.count, updated: Date()))
        return out
    }

    static func read(_ bundle: String) -> Package? {
        let plistPath = bundle + "/Contents/Info.plist"
        guard let d = FS.read(plistPath),
              let pl = (try? PropertyListSerialization.propertyList(from: d, format: nil)) as? [String: Any] else { return nil }
        let name = (pl["CFBundleDisplayName"] as? String) ?? (pl["CFBundleName"] as? String) ?? ((bundle as NSString).lastPathComponent as NSString).deletingPathExtension
        let short = (pl["CFBundleShortVersionString"] as? String)?.trimmed ?? ""
        let build = (pl["CFBundleVersion"] as? String)?.trimmed ?? ""
        var p = Package(ecosystem: .app, name: name, version: short.isEmpty ? build : short, location: bundle, source: "Info.plist")
        p.bundleID = pl["CFBundleIdentifier"] as? String
        if !build.isEmpty && build != p.version { p.build = build }
        if let feed = (pl["SUFeedURL"] as? String)?.trimmed, feed.hasPrefix("https://") { p.feedURL = feed }
        p.appStore = FS.exists(bundle + "/Contents/_MASReceipt/receipt")
        p.modified = FS.mtime(plistPath)
        return p
    }

    /// Apple's own bundled apps are updated with macOS and covered by the system checks.
    static func isApple(_ p: Package) -> Bool {
        (p.bundleID ?? "").hasPrefix("com.apple.") && p.bundleID != "com.apple.Safari" && p.bundleID != "com.apple.dt.Xcode"
    }
}
