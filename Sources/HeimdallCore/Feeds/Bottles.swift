import Foundation

/// When Homebrew had a fix, as opposed to when the fix existed. Bottles have been OCI images
/// on ghcr.io since Homebrew 3.2.7, and the image index for a formula version carries
/// `org.opencontainers.image.created` — the day that version became installable. Neither
/// `brew info --json` nor the formulae.brew.sh API keeps version history, so this is the only
/// cheap source for the packaging date.
///
/// A published bottle never changes, so an answer is cached forever and a miss for a day.
public enum Bottles {
    struct Entry: Codable {
        var created: Date?
        var fetched: Date
    }

    static let registry = "https://ghcr.io/v2/homebrew/core"
    static let tokenURL = "https://ghcr.io/token?service=ghcr.io&scope=repository:homebrew/core/%@:pull"

    /// Homebrew publishes `openssl@3` as `openssl/3`.
    static func path(_ formula: String) -> String { formula.replacingOccurrences(of: "@", with: "/") }

    /// The day a bottle for this formula version appeared, or nil when there isn't one
    /// (head-only formulae, versions older than the ghcr move, a name we can't map).
    public static func created(formula: String, version: String, offline: Bool) async -> Date? {
        let cache = DiskCache("feeds")
        var map = cache.get("bottles.json", [String: Entry].self) ?? [:]
        let key = "\(formula)@\(version)"
        if let e = map[key] {
            // A hit is permanent; a miss is worth retrying tomorrow in case the bottle landed.
            if e.created != nil || Date().timeIntervalSince(e.fetched) < 86400 { return e.created }
        }
        guard !offline else { return nil }
        let created = await fetch(formula: formula, version: version)
        map[key] = Entry(created: created, fetched: Date())
        cache.put("bottles.json", map)
        return created
    }

    static func fetch(formula: String, version: String) async -> Date? {
        let repo = path(formula)
        guard let escaped = repo.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed),
              let tag = version.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) else { return nil }
        // ghcr hands out an anonymous pull token for public repositories.
        var bearer = "QQ=="
        if let d = try? await HTTP.get(String(format: tokenURL, escaped)),
           let t = (jsonObject(d) as? [String: Any])?["token"] as? String, !t.isEmpty {
            bearer = t
        }
        guard let d = try? await HTTP.get("\(registry)/\(escaped)/manifests/\(tag)", headers: [
            "Authorization": "Bearer \(bearer)",
            "Accept": "application/vnd.oci.image.index.v1+json",
        ]) else { return nil }
        guard let j = jsonObject(d) as? [String: Any] else { return nil }
        if let s = (j["annotations"] as? [String: String])?["org.opencontainers.image.created"], let date = day(s) { return date }
        // Older indexes put the annotation on the per-platform manifests instead.
        for m in j["manifests"] as? [[String: Any]] ?? [] {
            if let s = (m["annotations"] as? [String: String])?["org.opencontainers.image.created"], let date = day(s) { return date }
        }
        return nil
    }

    /// The newest version Homebrew has a bottle for. `brew info` does not tell us this for
    /// formulae — it only says whether one is outdated — so the registry is asked directly.
    /// Tag lists move, so they are cached for a day rather than forever.
    public static func newest(formula: String, offline: Bool) async -> String? {
        let cache = DiskCache("feeds")
        var map = cache.get("bottle-tags.json", [String: TagList].self) ?? [:]
        if let e = map[formula], Date().timeIntervalSince(e.fetched) < 86400 { return e.newest }
        guard !offline else { return map[formula]?.newest }
        let tags = await fetchTags(formula: formula)
        let newest = pick(tags)
        map[formula] = TagList(newest: newest, fetched: Date())
        cache.put("bottle-tags.json", map)
        return newest
    }

    struct TagList: Codable { var newest: String?; var fetched: Date }
    struct AllTags: Codable { var tags: [String]; var fetched: Date }

    /// The day the first bottle carrying a fix appeared. Homebrew often skips upstream
    /// releases (the fix lands in 3.0.14, Homebrew goes 3.0.13 → 3.0.15), so asking for the
    /// fixed version's own bottle comes back empty far more often than not. When it does,
    /// take the earliest bottled version at or above the fix instead.
    public static func firstWithFix(formula: String, fixed: String, offline: Bool) async -> Date? {
        if let d = await created(formula: formula, version: fixed, offline: offline) { return d }
        let tags = await allTags(formula: formula, offline: offline)
        func base(_ t: String) -> String {
            let noRebuild = t.components(separatedBy: "-").first ?? t
            return noRebuild.components(separatedBy: "_").first ?? noRebuild
        }
        let candidates = tags.filter { Version.compare(base($0), fixed) >= 0 }
            .sorted { Version.less(base($0), base($1)) || (base($0) == base($1) && $0.count < $1.count) }
        guard let first = candidates.first, first != fixed else { return nil }
        return await created(formula: formula, version: first, offline: offline)
    }

    static func allTags(formula: String, offline: Bool) async -> [String] {
        let cache = DiskCache("feeds")
        var map = cache.get("bottle-alltags.json", [String: AllTags].self) ?? [:]
        if let e = map[formula], offline || Date().timeIntervalSince(e.fetched) < 86400 { return e.tags }
        guard !offline else { return [] }
        let tags = await fetchTags(formula: formula)
        map[formula] = AllTags(tags: tags, fetched: Date())
        cache.put("bottle-alltags.json", map)
        return tags
    }

    static func fetchTags(formula: String) async -> [String] {
        let repo = path(formula)
        guard let escaped = repo.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) else { return [] }
        var bearer = "QQ=="
        if let d = try? await HTTP.get(String(format: tokenURL, escaped)),
           let tok = (jsonObject(d) as? [String: Any])?["token"] as? String, !tok.isEmpty { bearer = tok }
        guard let d = try? await HTTP.get("\(registry)/\(escaped)/tags/list", headers: ["Authorization": "Bearer \(bearer)"]),
              let j = jsonObject(d) as? [String: Any] else { return [] }
        return j["tags"] as? [String] ?? []
    }

    /// Tags are not in order, and carry two kinds of suffix: `_1` is a Homebrew revision of
    /// the same upstream version, `-1` is a rebuild of the same bottle. Compare on the
    /// upstream part and prefer the plainest tag for a given version.
    static func pick(_ tags: [String]) -> String? {
        let cleaned = tags.map { t -> (tag: String, base: String) in
            (t, t.components(separatedBy: "-").first ?? t)
        }
        guard let best = cleaned.map(\.base).max(by: { Version.compareBrew($0, $1) < 0 }) else { return nil }
        let sameVersion = cleaned.filter { $0.base == best }
        return sameVersion.first(where: { $0.tag == best })?.tag ?? sameVersion.first?.tag
    }

    /// The annotation is "2023-08-15" on most bottles and full RFC 3339 on some.
    static func day(_ s: String) -> Date? {
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime]
        if let d = iso.date(from: s) { return d }
        let f = DateFormatter()
        f.calendar = Calendar(identifier: .gregorian)
        f.timeZone = TimeZone(secondsFromGMT: 0)
        f.dateFormat = "yyyy-MM-dd"
        return f.date(from: s)
    }
}
