import Foundation

/// OSV.dev — exact version matching for PyPI, npm, crates.io, RubyGems, Go and (by git tag)
/// Homebrew formulae. Only package names and versions are sent.
public enum OSVClient {
    static let batchURL = "https://api.osv.dev/v1/querybatch"
    static let vulnURL = "https://api.osv.dev/v1/vulns/"

    struct Query: Hashable { var pkgIndex: Int; var ecosystem: String; var name: String; var version: String }

    public static func match(_ packages: [Package], offline: Bool) async -> ([String: [Vulnerability]], SourceStatus) {
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

        let cache = DiskCache("osv")
        // A batch answer is reused for 6 hours as long as the package set is the same.
        let fingerprint = stableHash(queries.map { "\($0.ecosystem)|\($0.name)|\($0.version)" }.joined(separator: ","))
        var ids: [[String]] = Array(repeating: [], count: queries.count)
        var batchNote = ""
        if let cached = cache.get("batch-\(fingerprint).json", [[String]].self, maxAge: offline ? nil : 6 * 3600), cached.count == queries.count {
            ids = cached; batchNote = "cached"
        } else if offline {
            return ([:], SourceStatus(name: "OSV.dev", state: .skipped, detail: "offline and no cached answer"))
        } else {
            do {
                for start in stride(from: 0, to: queries.count, by: 1000) {
                    let chunk = Array(queries[start..<min(start + 1000, queries.count)])
                    let body: [String: Any] = ["queries": chunk.map { q in
                        q.ecosystem == "GIT"
                            ? ["package": ["name": q.name, "ecosystem": "GIT"], "version": q.version] as [String: Any]
                            : ["package": ["name": q.name, "ecosystem": q.ecosystem], "version": q.version] as [String: Any]
                    }]
                    let d = try await HTTP.postJSON(batchURL, try JSONSerialization.data(withJSONObject: body))
                    let results = (jsonObject(d) as? [String: Any])?["results"] as? [[String: Any]] ?? []
                    for (j, r) in results.enumerated() where start + j < ids.count {
                        ids[start + j] = (r["vulns"] as? [[String: Any]] ?? []).compactMap { $0["id"] as? String }
                    }
                }
                cache.put("batch-\(fingerprint).json", ids)
                batchNote = "queried"
            } catch {
                return ([:], SourceStatus(name: "OSV.dev", state: .failed, detail: "querybatch failed: \(error)"))
            }
        }

        // Details for each advisory id, cached for a week.
        let allIDs = ids.flatMap { $0 }.uniqued()
        let details: [(String, [String: Any]?)] = await concurrentMap(allIDs, width: 8) { id in
            if let d = cache.data("vuln-\(id).json", maxAge: offline ? nil : 7 * 86400), let j = jsonObject(d) as? [String: Any] { return (id, j) }
            if offline { return (id, nil) }
            guard let d = try? await HTTP.get(vulnURL + (id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id)) else { return (id, nil) }
            cache.store("vuln-\(id).json", d)
            return (id, jsonObject(d) as? [String: Any])
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
        let hits = out.values.reduce(0) { $0 + $1.count }
        return (out, SourceStatus(name: "OSV.dev", state: .ok, detail: "\(queries.count) lookups (\(batchNote)), \(allIDs.count) advisories", count: hits, updated: Date()))
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
