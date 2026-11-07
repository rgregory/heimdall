import Foundation

/// CISA Known Exploited Vulnerabilities catalog — cached for 12 hours.
public struct KEVCatalog: Sendable {
    public var entries: [String: KEVEntry] = [:]
    public var version: String = ""
    public var released: String = ""
    public var fetched: Date? = nil

    public static let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    public subscript(cve: String) -> KEVEntry? { entries[cve] }

    public func first(of ids: [String]) -> KEVEntry? { ids.lazy.compactMap { entries[$0] }.first }

    public static func load(offline: Bool) async -> (KEVCatalog, SourceStatus) {
        let cache = DiskCache("feeds")
        var data = cache.data("kev.json", maxAge: offline ? nil : 12 * 3600)
        var note = "cached"
        if data == nil && !offline {
            do { data = try await HTTP.get(url); cache.store("kev.json", data!); note = "downloaded" }
            catch { data = cache.data("kev.json"); note = "download failed (\(error)); using cached copy" }
        }
        guard let data, let cat = parse(data) else {
            return (KEVCatalog(), SourceStatus(name: "CISA KEV", state: .failed, detail: "catalog unavailable — exploited flags will be missing"))
        }
        var c = cat
        c.fetched = FS.mtime(cache.url("kev.json").path)
        return (c, SourceStatus(name: "CISA KEV", state: note.hasPrefix("download failed") ? .warning : .ok,
                                detail: "catalog \(c.version) (\(note))", count: c.entries.count, updated: c.fetched))
    }

    public static func parse(_ data: Data) -> KEVCatalog? {
        struct Raw: Decodable { var catalogVersion: String?; var dateReleased: String?; var vulnerabilities: [R] }
        struct R: Decodable {
            var cveID: String; var vendorProject: String?; var product: String?; var vulnerabilityName: String?
            var dateAdded: String?; var shortDescription: String?; var requiredAction: String?; var dueDate: String?
            var knownRansomwareCampaignUse: String?
        }
        guard let raw = try? JSONDecoder().decode(Raw.self, from: data), !raw.vulnerabilities.isEmpty else { return nil }
        var c = KEVCatalog(version: raw.catalogVersion ?? "", released: raw.dateReleased ?? "")
        for r in raw.vulnerabilities {
            c.entries[r.cveID] = KEVEntry(cveID: r.cveID, vendorProject: r.vendorProject ?? "", product: r.product ?? "",
                                          vulnerabilityName: r.vulnerabilityName ?? "", dateAdded: r.dateAdded ?? "",
                                          shortDescription: r.shortDescription ?? "", requiredAction: r.requiredAction ?? "",
                                          dueDate: r.dueDate ?? "", knownRansomwareCampaignUse: r.knownRansomwareCampaignUse ?? "")
        }
        return c
    }
}

/// FIRST.org Exploit Prediction Scoring System — probability of exploitation in the next 30 days.
public enum EPSS {
    struct Entry: Codable { var epss: Double; var percentile: Double; var fetched: Date }

    public static func scores(for cves: [String], offline: Bool) async -> ([String: (Double, Double)], SourceStatus) {
        let cache = DiskCache("feeds")
        var map = cache.get("epss.json", [String: Entry].self) ?? [:]
        let stale = cves.uniqued().filter { map[$0].map { Date().timeIntervalSince($0.fetched) > 86400 } ?? true }
        var failed: Error?
        if !offline {
            for chunk in stride(from: 0, to: stale.count, by: 100).map({ Array(stale[$0..<min($0 + 100, stale.count)]) }) {
                do {
                    let d = try await HTTP.get("https://api.first.org/data/v1/epss?cve=" + chunk.joined(separator: ","))
                    let rows = (jsonObject(d) as? [String: Any])?["data"] as? [[String: Any]] ?? []
                    for r in rows {
                        guard let c = r["cve"] as? String else { continue }
                        map[c] = Entry(epss: Double("\(r["epss"] ?? "")") ?? 0, percentile: Double("\(r["percentile"] ?? "")") ?? 0, fetched: Date())
                    }
                    // CVEs EPSS doesn't know yet: remember the miss so we don't ask again today.
                    for c in chunk where map[c] == nil { map[c] = Entry(epss: -1, percentile: -1, fetched: Date()) }
                } catch { failed = error; break }
            }
            cache.put("epss.json", map)
        }
        var out: [String: (Double, Double)] = [:]
        for c in cves { if let e = map[c], e.epss >= 0 { out[c] = (e.epss, e.percentile) } }
        let st = failed.map { SourceStatus(name: "FIRST EPSS", state: .warning, detail: "partial: \($0)", count: out.count) }
            ?? SourceStatus(name: "FIRST EPSS", state: cves.isEmpty ? .skipped : .ok, detail: cves.isEmpty ? "no CVEs to score" : "exploit-probability scores", count: out.count, updated: Date())
        return (out, st)
    }
}
