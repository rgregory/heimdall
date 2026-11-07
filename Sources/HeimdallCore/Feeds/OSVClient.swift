import Foundation

/// OSV.dev — exact version matching for PyPI, npm, crates.io, RubyGems, Go and (by git tag)
/// Homebrew formulae. Only package names and versions are sent.
public enum OSVClient {
    static let batchURL = "https://api.osv.dev/v1/querybatch"
    static let vulnURL = "https://api.osv.dev/v1/vulns/"

    struct Query: Hashable { var pkgIndex: Int; var ecosystem: String; var name: String; var version: String }

    public static func match(_ packages: [Package], offline: Bool) async -> ([String: [Vulnerability]], SourceStatus) {
        await match(packages, offline: offline, cache: DiskCache("osv"), post: { try await HTTP.postJSON(batchURL, $0) },
                    get: { try await HTTP.get($0) })
    }

    static func match(_ packages: [Package], offline: Bool, cache: DiskCache,
                      post: (Data) async throws -> Data,
                      get: @escaping @Sendable (String) async throws -> Data) async -> ([String: [Vulnerability]], SourceStatus) {
        var queries: [Query] = []
        for (i, p) in packages.enumerated() {
            if let eco = p.ecosystem.osvName {
                let name = p.ecosystem == .pypi ? LanguageCollector.pep503(p.name) : p.name
                queries.append(Query(pkgIndex: i, ecosystem: eco, name: name, version: p.version))
            } else if p.ecosystem == .homebrew, let repo = p.repo {
                // Formulae have no OSV ecosystem; try the upstream repo's release tag both ways.
                for tag in [p.version, "v" + p.version].uniqued() { queries.append(Query(pkgIndex: i, ecosystem: "GIT", name: repo, version: tag)) }
            }
        }
        guard !queries.isEmpty else { return ([:], SourceStatus(name: "OSV.dev", state: .skipped, detail: "no packages to check")) }

        // A batch answer is reused for 6 hours as long as the package set is the same.
        let fingerprint = stableHash(queries.map { "\($0.ecosystem)|\($0.name)|\($0.version)" }.joined(separator: ","))
        var ids: [[String]] = Array(repeating: [], count: queries.count)
        var batchNote = ""
        var warning = false
        if let cached = cache.get("batch-\(fingerprint).json", [[String]].self, maxAge: offline ? nil : 6 * 3600), cached.count == queries.count {
            ids = cached; batchNote = "cached"
        } else if offline {
            return ([:], SourceStatus(name: "OSV.dev", state: .skipped, detail: "offline and no cached answer"))
        } else {
            do {
                for start in stride(from: 0, to: queries.count, by: 1000) {
                    let chunk = Array(queries[start..<min(start + 1000, queries.count)])
                    let results = try await queryIDs(chunk, post: post)
                    for (j, result) in results.enumerated() { ids[start + j] = result }
                }
                cache.put("batch-\(fingerprint).json", ids)
                batchNote = "queried"
            } catch {
                guard let previous = cache.get("batch-\(fingerprint).json", [[String]].self), previous.count == queries.count else {
                    return ([:], SourceStatus(name: "OSV.dev", state: .failed, detail: "querybatch failed: \(error)"))
                }
                ids = previous
                warning = true
                batchNote = "refresh failed; using cached answer: \(error)"
            }
        }

        // Details for each advisory id, cached for a week.
        let allIDs = ids.flatMap { $0 }.uniqued()
        let details: [(String, [String: Any]?)] = await concurrentMap(allIDs, width: 8) { id in
            if let d = cache.data("vuln-\(id).json", maxAge: offline ? nil : 7 * 86400), let j = jsonObject(d) as? [String: Any] { return (id, j) }
            if offline { return (id, nil) }
            guard let d = try? await get(vulnURL + (id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id)),
                  let j = jsonObject(d) as? [String: Any], j["id"] as? String == id else { return (id, nil) }
            cache.store("vuln-\(id).json", d)
            return (id, j)
        }
        let byID = Dictionary(details.map { ($0.0, $0.1) }, uniquingKeysWith: { a, _ in a })

        var out: [String: [Vulnerability]] = [:]
        for (qi, q) in queries.enumerated() {
            let pkg = packages[q.pkgIndex]
            for id in ids[qi] {
                guard let j = byID[id] ?? nil else {
                    var v = Vulnerability(id: id); v.source = "OSV"; out[pkg.id, default: []].append(v); continue
                }
                if j["withdrawn"] != nil { continue }
                out[pkg.id, default: []].append(vulnerability(j, ecosystem: q.ecosystem, package: q.name))
            }
        }
        // GIT queries can return the same advisory twice (tag and v-tag).
        for (k, v) in out { var seen = Set<String>(); out[k] = v.filter { seen.insert($0.id).inserted } }
        warning = warning || details.contains { $0.1 == nil }
        let hits = out.values.reduce(0) { $0 + $1.count }
        return (out, SourceStatus(name: "OSV.dev", state: warning ? .warning : .ok, detail: "\(queries.count) lookups (\(batchNote)), \(allIDs.count) advisories\(details.contains { $0.1 == nil } ? "; some advisory details unavailable" : "")", count: hits, updated: Date()))
    }

    private struct Batch: Decodable { var results: [Result] }
    private struct Result: Decodable {
        struct ID: Decodable { var id: String }
        var vulns: [ID]?
        var next_page_token: String?
    }

    /// Keep each token paired with its original query; finished queries are not sent again.
    static func queryIDs(_ queries: [Query], post: (Data) async throws -> Data) async throws -> [[String]] {
        var ids = [[String]](repeating: [], count: queries.count)
        var pending = Array(queries.indices)
        var tokens: [Int: String] = [:]
        var seen = [Set<String>](repeating: [], count: queries.count)
        var pages = 0
        while !pending.isEmpty {
            try Task.checkCancellation()
            pages += 1
            guard pages <= 100 else { throw FeedError.invalid("OSV pagination limit exceeded") }
            let body: [String: Any] = ["queries": pending.map { i -> [String: Any] in
                let q = queries[i]
                var item: [String: Any] = ["package": ["name": q.name, "ecosystem": q.ecosystem], "version": q.version]
                if let token = tokens[i] { item["page_token"] = token }
                return item
            }]
            let data = try await post(JSONSerialization.data(withJSONObject: body))
            let response = try JSONDecoder().decode(Batch.self, from: data)
            guard response.results.count == pending.count else { throw FeedError.invalid("OSV result count does not match query count") }
            var next: [Int] = []
            for (i, result) in zip(pending, response.results) {
                for v in result.vulns ?? [] {
                    guard !v.id.isEmpty else { throw FeedError.invalid("OSV advisory has no ID") }
                    ids[i].append(v.id)
                }
                if let token = result.next_page_token, !token.isEmpty {
                    guard seen[i].insert(token).inserted else { throw FeedError.invalid("OSV repeated a page token") }
                    tokens[i] = token
                    next.append(i)
                }
            }
            pending = next
        }
        return ids.map { $0.uniqued() }
    }

    static func vulnerability(_ j: [String: Any], ecosystem: String, package: String) -> Vulnerability {
        var v = Vulnerability(id: j["id"] as? String ?? "?")
        v.aliases = (j["aliases"] as? [String] ?? []) + (j["upstream"] as? [String] ?? []).filter { $0.hasPrefix("CVE-") }
        v.aliases = v.aliases.uniqued().filter { $0 != v.id }
        let summary = (j["summary"] as? String) ?? (j["details"] as? String) ?? ""
        v.summary = String(summary.split(separator: "\n").first ?? "").trimmed.prefix(400).description
        v.published = parseDate(j["published"] as? String)
        v.references = (j["references"] as? [[String: Any]] ?? []).compactMap { $0["url"] as? String }.prefix(10).map { $0 }
        v.source = "OSV"

        // Severity: CVSS vector first, then the database's own label.
        for s in j["severity"] as? [[String: Any]] ?? [] {
            guard let type = s["type"] as? String, let score = s["score"] as? String else { continue }
            if type.hasPrefix("CVSS_V3"), let b = CVSS.baseScore(score) { v.cvss = b; v.vector = score; v.severity = Severity(score: b) }
            else if v.vector == nil { v.vector = score }
        }
        let affected = j["affected"] as? [[String: Any]] ?? []
        if v.cvss == nil {
            let labels = [((j["database_specific"] as? [String: Any])?["severity"] as? String)] +
                affected.map { (($0["ecosystem_specific"] as? [String: Any])?["severity"] as? String) ?? (($0["database_specific"] as? [String: Any])?["severity"] as? String) }
            if let l = labels.compactMap({ $0 }).first { v.severity = Severity(label: l) }
        }
        // Fixed versions for this package.
        for a in affected {
            let p = a["package"] as? [String: Any]
            let name = (p?["name"] as? String) ?? ""
            let same = ecosystem == "GIT" || name.lowercased() == package.lowercased() || LanguageCollector.pep503(name) == package
            guard same else { continue }
            for r in a["ranges"] as? [[String: Any]] ?? [] {
                let isGit = (r["type"] as? String) == "GIT"
                for e in r["events"] as? [[String: Any]] ?? [] {
                    if let f = e["fixed"] as? String { v.fixed.append(isGit ? "commit \(f.prefix(10))" : f) }
                }
            }
        }
        v.fixed = v.fixed.uniqued().sorted { Version.less($0, $1) }
        return v
    }
}

/// Reader for `brew vulns --json`. The shape isn't documented, so look for any object with a
/// package name and a list of advisories.
public enum BrewVulnsParser {
    public static func parse(_ data: Data) -> [String: [Vulnerability]] {
        var out: [String: [Vulnerability]] = [:]
        func visit(_ x: Any, _ depth: Int) {
            guard depth < 7 else { return }
            if let a = x as? [Any] { a.forEach { visit($0, depth + 1) }; return }
            guard let o = x as? [String: Any] else { return }
            let list = (o["vulnerabilities"] ?? o["vulns"] ?? o["advisories"]) as? [[String: Any]]
            let name = (o["name"] as? String) ?? (o["formula"] as? String) ?? ((o["package"] as? [String: Any])?["name"] as? String) ?? (o["package"] as? String)
            if let list, let name {
                out[name, default: []] += list.map { e in
                    var v = Vulnerability(id: (e["id"] as? String) ?? (e["cve"] as? String) ?? "?")
                    v.aliases = (e["aliases"] as? [String] ?? []).filter { $0 != v.id }
                    v.summary = String(((e["summary"] as? String) ?? (e["title"] as? String) ?? "").prefix(400))
                    let sev = (e["severity"] as? String) ?? ((e["database_specific"] as? [String: Any])?["severity"] as? String) ?? ""
                    v.severity = Severity(label: sev)
                    if let s = e["cvss"] as? Double { v.cvss = s; v.severity = Severity(score: s) }
                    let fixed = (e["fixed_version"] ?? e["fixed"] ?? e["fixedVersion"] ?? e["fixed_versions"])
                    if let f = fixed as? String, !f.isEmpty { v.fixed = [f] } else if let f = fixed as? [String] { v.fixed = f }
                    v.source = "brew vulns"
                    return v
                }
                return
            }
            o.values.forEach { visit($0, depth + 1) }
        }
        if let j = jsonObject(data) { visit(j, 0) }
        return out
    }
}
