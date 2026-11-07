import Foundation

// Signals layered onto advisories after matching: more exploited-in-the-wild lists, public
// exploit availability, and CVE-program scores for advisories NVD/OSV left unrated.

// MARK: - Exploited-in-the-wild lists beyond CISA KEV

public struct ExploitedList: Sendable {
    public var entries: [String: KEVEntry] = [:]
}

public enum EUVDExploited {
    public static func load(offline: Bool) async -> (ExploitedList, SourceStatus) {
        let cache = DiskCache("feeds")
        if let c = cache.get("euvd-exploited.json", [String: KEVEntry].self, maxAge: offline ? nil : 12 * 3600) {
            return (ExploitedList(entries: c), SourceStatus(name: "EUVD exploited", state: .ok, detail: "ENISA's exploited list (cached)", count: c.count, updated: FS.mtime(cache.url("euvd-exploited.json").path)))
        }
        if offline { return (ExploitedList(), SourceStatus(name: "EUVD exploited", state: .skipped, detail: "offline and not cached")) }
        var map: [String: KEVEntry] = [:]
        var failed: Error?
        for page in 0..<60 {
            do {
                let d = try await HTTP.get("https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities?size=100&page=\(page)")
                let rows = jsonObject(d) as? [[String: Any]] ?? []
                for r in rows {
                    let aliases = (r["aliases"] as? String ?? "").split(whereSeparator: \.isNewline).map { String($0).trimmed }
                    let vendor = ((r["enisaIdVendor"] as? [[String: Any]])?.first?["vendor"] as? [String: Any])?["name"] as? String ?? ""
                    for cve in aliases where cve.hasPrefix("CVE-") {
                        map[cve] = KEVEntry(cveID: cve, vendorProject: vendor, product: "", vulnerabilityName: r["id"] as? String ?? "",
                                            dateAdded: r["exploitedSince"] as? String ?? "", shortDescription: String((r["description"] as? String ?? "").prefix(300)),
                                            requiredAction: "", dueDate: "", knownRansomwareCampaignUse: "", source: "EUVD")
                    }
                }
                if rows.count < 100 { break }
            } catch { failed = error; break }
        }
        if !map.isEmpty { cache.put("euvd-exploited.json", map) }
        return (ExploitedList(entries: map), SourceStatus(name: "EUVD exploited", state: failed == nil ? .ok : .warning,
                                                          detail: failed.map { "partial: \($0)" } ?? "ENISA's exploited-vulnerabilities list", count: map.count, updated: Date()))
    }
}

public enum VulnCheckKEV {
    public static func load(token: String?, offline: Bool) async -> (ExploitedList, SourceStatus) {
        guard let token, !token.isEmpty else {
            return (ExploitedList(), SourceStatus(name: "VulnCheck KEV", state: .skipped, detail: "add a free VulnCheck API token in Settings to use it"))
        }
        let cache = DiskCache("feeds")
        if let c = cache.get("vulncheck-kev.json", [String: KEVEntry].self, maxAge: offline ? nil : 12 * 3600) {
            return (ExploitedList(entries: c), SourceStatus(name: "VulnCheck KEV", state: .ok, detail: "cached", count: c.count))
        }
        if offline { return (ExploitedList(), SourceStatus(name: "VulnCheck KEV", state: .skipped, detail: "offline and not cached")) }
        var map: [String: KEVEntry] = [:]
        var failed: Error?
        var page = 1, pages = 1
        repeat {
            do {
                let d = try await HTTP.get("https://api.vulncheck.com/v3/index/vulncheck-kev?limit=100&page=\(page)", headers: ["Authorization": "Bearer \(token)", "Accept": "application/json"])
                let j = jsonObject(d) as? [String: Any] ?? [:]
                pages = ((j["_meta"] as? [String: Any])?["total_pages"] as? Int) ?? pages
                let rows = j["data"] as? [[String: Any]] ?? []
                for r in rows {
                    let cves = (r["cve"] as? [String]) ?? [(r["cve"] as? String) ?? ""]
                    for cve in cves where cve.hasPrefix("CVE-") {
                        map[cve] = KEVEntry(cveID: cve, vendorProject: r["vendorProject"] as? String ?? "", product: r["product"] as? String ?? "",
                                            vulnerabilityName: r["vulnerabilityName"] as? String ?? "", dateAdded: String((r["date_added"] as? String ?? r["dateAdded"] as? String ?? "").prefix(10)),
                                            shortDescription: r["shortDescription"] as? String ?? "", requiredAction: r["required_action"] as? String ?? "",
                                            dueDate: "", knownRansomwareCampaignUse: r["knownRansomwareCampaignUse"] as? String ?? "", source: "VulnCheck KEV")
                    }
                }
                if rows.isEmpty { break }
                page += 1
            } catch { failed = error; break }
        } while page <= min(pages, 200)
        if !map.isEmpty { cache.put("vulncheck-kev.json", map) }
        return (ExploitedList(entries: map), SourceStatus(name: "VulnCheck KEV", state: failed == nil ? .ok : .warning,
                                                          detail: failed.map { "\($0)" } ?? "VulnCheck's exploited list", count: map.count, updated: Date()))
    }
}

// MARK: - Public exploit availability

public enum ExploitIndex {
    /// CVE → ["Exploit-DB", "Metasploit", "nuclei"].
    public static func load(offline: Bool) async -> ([String: [String]], SourceStatus) {
        let cache = DiskCache("feeds")
        if let c = cache.get("exploit-index.json", [String: [String]].self, maxAge: offline ? nil : 86400) {
            return (c, SourceStatus(name: "Public exploits", state: .ok, detail: "Exploit-DB, Metasploit, nuclei (cached)", count: c.count, updated: FS.mtime(cache.url("exploit-index.json").path)))
        }
        var map: [String: Set<String>] = [:]
        var notes: [String] = []
        func add(_ text: String, _ source: String) {
            var n = 0
            for m in text.allMatches(#"CVE-\d{4}-\d{4,}"#) { map[m[0], default: []].insert(source); n += 1 }
            notes.append("\(source) \(n > 0 ? "✓" : "✕")")
        }
        if !offline {
            if let d = try? await HTTP.get("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv", maxBytes: 64 * 1024 * 1024) { add(String(decoding: d, as: UTF8.self), "Exploit-DB") } else { notes.append("Exploit-DB ✕") }
            if let d = try? await HTTP.get("https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json", maxBytes: 128 * 1024 * 1024) { add(String(decoding: d, as: UTF8.self), "Metasploit") } else { notes.append("Metasploit ✕") }
        }
        // nuclei: your local checkout first (file names are CVE ids), else the upstream index.
        let local = nucleiLocal()
        if !local.isEmpty { for c in local { map[c, default: []].insert("nuclei") }; notes.append("nuclei (local ~/nuclei-templates) ✓") }
        else if !offline, let d = try? await HTTP.get("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json") { add(String(decoding: d, as: UTF8.self), "nuclei") }
        let out = map.mapValues { Array($0).sorted() }
        if !out.isEmpty { cache.put("exploit-index.json", out) }
        return (out, SourceStatus(name: "Public exploits", state: out.isEmpty ? .warning : .ok, detail: notes.joined(separator: ", "), count: out.count, updated: Date()))
    }

    static func nucleiLocal() -> Set<String> {
        let root = Paths.expand("~/nuclei-templates")
        guard FS.isDir(root), let e = FileManager.default.enumerator(atPath: root) else { return [] }
        var out = Set<String>()
        while let f = e.nextObject() as? String {
            let name = (f as NSString).lastPathComponent
            if name.hasPrefix("CVE-"), name.hasSuffix(".yaml") { out.insert(String(name.dropLast(5)).uppercased()) }
        }
        return out
    }
}

// MARK: - CVE program records (cvelistV5) and CISA Vulnrichment

public enum CVERecords {
    public struct Info: Codable { var cvss: Double?; var vector: String?; var exploitation: String?; var title: String? }

    static func path(_ cve: String) -> String? {
        guard let m = cve.firstMatch(#"^CVE-(\d{4})-(\d+)$"#), let n = Int(m[2]) else { return nil }
        return "\(m[1])/\(n / 1000)xxx/\(cve).json"
    }

    /// Scores and SSVC exploitation for CVEs that lack them, from CISA's ADP container first, then the CNA's own record.
    public static func enrich(_ cves: [String], offline: Bool) async -> [String: Info] {
        let cache = DiskCache("cve-records")
        let results: [(String, Info?)] = await concurrentMap(Array(cves.uniqued().prefix(300)), width: 8) { cve in
            if let c = cache.get(cve + ".json", Info.self, maxAge: offline ? nil : 7 * 86400) { return (cve, c) }
            guard !offline, let p = path(cve) else { return (cve, nil) }
            var info = Info()
            if let d = try? await HTTP.get("https://raw.githubusercontent.com/cisagov/vulnrichment/develop/" + p), let j = jsonObject(d) as? [String: Any] {
                read(j, into: &info)
            }
            if info.cvss == nil, let d = try? await HTTP.get("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/" + p), let j = jsonObject(d) as? [String: Any] {
                read(j, into: &info)
            }
            cache.put(cve + ".json", info)   // misses too, so we don't ask again this week
            return (cve, info)
        }
        var out: [String: Info] = [:]
        for (c, i) in results { if let i { out[c] = i } }
        return out
    }

    static func read(_ j: [String: Any], into info: inout Info) {
        let c = j["containers"] as? [String: Any] ?? [:]
        let containers = ((c["adp"] as? [[String: Any]]) ?? []) + [c["cna"] as? [String: Any] ?? [:]]
        for k in containers {
            for m in k["metrics"] as? [[String: Any]] ?? [] {
                for key in ["cvssV3_1", "cvssV3_0", "cvssV4_0"] {
                    if info.cvss == nil, let x = m[key] as? [String: Any], let s = x["baseScore"] as? Double {
                        info.cvss = s; info.vector = x["vectorString"] as? String
                    }
                }
                if let o = m["other"] as? [String: Any], (o["type"] as? String) == "ssvc",
                   let opts = (o["content"] as? [String: Any])?["options"] as? [[String: Any]] {
                    for opt in opts { if let e = opt["Exploitation"] as? String { info.exploitation = e } }
                }
            }
            if info.title == nil, let t = k["title"] as? String, !t.contains("Program Container") { info.title = t }
        }
    }
}
