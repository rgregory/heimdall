import Foundation

/// "Is there a newer version?" for apps, CVEs or not: the app's own Sparkle feed, the Mac App
/// Store, or Homebrew's cask index. Sets `latest` / `outdated` on packages.
public enum UpdateChecks {
    public static func apply(_ packages: inout [Package], offline: Bool) async -> SourceStatus {
        let cache = DiskCache("updates")
        let apps = packages.indices.filter { packages[$0].ecosystem == .app && !packages[$0].version.isEmpty && !AppCollector.isApple(packages[$0]) }
        var bySparkle = 0, byStore = 0, byCask = 0

        // 1. Sparkle appcasts
        let feeds = apps.filter { packages[$0].feedURL != nil }.prefix(80).map { ($0, packages[$0].feedURL!) }
        let sparkle: [(Int, String?)] = await concurrentMap(Array(feeds), width: 8) { item in
            let key = "sparkle-" + stableHash(item.1) + ".xml"
            var d = cache.data(key, maxAge: offline ? nil : 86400)
            if d == nil && !offline { d = try? await HTTP.get(item.1, maxBytes: 2 * 1024 * 1024); if let d { cache.store(key, d) } }
            return (item.0, d.flatMap { latestInAppcast(String(decoding: $0, as: UTF8.self)) })
        }
        for (i, v) in sparkle { if let v, set(&packages[i], v, "Sparkle feed") { bySparkle += 1 } }

        // 2. Mac App Store
        let store = apps.filter { packages[$0].appStore && packages[$0].latest == nil && packages[$0].bundleID != nil }.map { ($0, packages[$0].bundleID!) }
        let storeVers: [(Int, String?)] = await concurrentMap(store, width: 6) { item in
            let key = "mas-" + item.1 + ".json"
            var d = cache.data(key, maxAge: offline ? nil : 86400)
            if d == nil && !offline { d = try? await HTTP.get("https://itunes.apple.com/lookup?bundleId=\(item.1)&country=us&entity=macSoftware"); if let d { cache.store(key, d) } }
            let r = ((jsonObject(d) as? [String: Any])?["results"] as? [[String: Any]])?.first
            return (item.0, r?["version"] as? String)
        }
        for (i, v) in storeVers { if let v, set(&packages[i], v, "Mac App Store") { byStore += 1 } }

        // 3. Homebrew cask index, by .app file name
        let caskIndex = await loadCaskIndex(offline: offline)
        for i in apps where packages[i].latest == nil && !packages[i].appStore {
            let file = (packages[i].location as NSString).lastPathComponent
            if let v = caskIndex[file], set(&packages[i], v, "Homebrew cask index") { byCask += 1 }
        }

        let outdated = packages.filter { $0.ecosystem == .app && $0.outdated }.count
        return SourceStatus(name: "Update checks", state: .ok,
                            detail: "\(outdated) apps have newer versions — via Sparkle feeds (\(bySparkle)), App Store (\(byStore)), cask index (\(byCask))",
                            count: outdated, updated: Date())
    }

    /// Records the latest version; returns true when the app is behind it.
    @discardableResult
    static func set(_ p: inout Package, _ latest: String, _ source: String) -> Bool {
        let l = latest.trimmed
        guard l.first?.isNumber == true else { return false }
        // Some feeds publish build numbers only; compare against the bundle build in that case.
        let installed = (p.build != nil && !l.contains(".") && p.build!.first?.isNumber == true) ? p.build! : p.version
        p.latest = l; p.latestSource = source
        let behind = Version.compare(l, installed) > 0
        if behind { p.outdated = true }
        return behind
    }

    /// Newest non-beta version in a Sparkle appcast.
    static func latestInAppcast(_ xml: String) -> String? {
        var best: String?
        for m in xml.allMatches(#"<item>([\s\S]*?)</item>"#) {
            let item = m[1]
            if item.contains("<sparkle:channel>") { continue }   // beta / nightly channels
            let short = item.firstMatch(#"sparkle:shortVersionString="([^"]+)""#)?[1]
                ?? item.firstMatch(#"<sparkle:shortVersionString>([^<]+)</sparkle:shortVersionString>"#)?[1]
                ?? item.firstMatch(#"sparkle:version="([^"]+)""#)?[1]
                ?? item.firstMatch(#"<sparkle:version>([^<]+)</sparkle:version>"#)?[1]
            guard let v = short?.trimmed, v.first?.isNumber == true else { continue }
            if best == nil || Version.compare(v, best!) > 0 { best = v }
        }
        return best
    }

    /// "Firefox.app" → "144.0.2", from formulae.brew.sh (reduced and cached for a day).
    static func loadCaskIndex(offline: Bool) async -> [String: String] {
        let cache = DiskCache("updates")
        if let c = cache.get("cask-index.json", [String: String].self, maxAge: offline ? nil : 86400) { return c }
        guard !offline, let d = try? await HTTP.get("https://formulae.brew.sh/api/cask.json", maxBytes: 64 * 1024 * 1024),
              let arr = jsonObject(d) as? [[String: Any]] else { return cache.get("cask-index.json", [String: String].self) ?? [:] }
        var map: [String: String] = [:]
        for c in arr {
            guard let raw = c["version"] as? String, raw != "latest" else { continue }
            let ver = String(raw.split(separator: ",").first ?? "")
            for name in BrewCollector.appNames(c) where map[name] == nil { map[name] = ver }
        }
        cache.put("cask-index.json", map)
        return map
    }
}
