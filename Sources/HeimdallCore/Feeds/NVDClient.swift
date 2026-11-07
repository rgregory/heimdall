import Foundation

/// A CVE from NVD, reduced to what Heimdall needs to decide applicability.
public struct NVDCve: Codable, Sendable {
    public struct Match: Codable, Sendable {
        var vulnerable: Bool
        var criteria: String
        var vsi: String?, vse: String?, vei: String?, vee: String?
    }
    public struct Node: Codable, Sendable { var op: String; var negate: Bool; var matches: [Match] }
    public struct Config: Codable, Sendable { var op: String; var nodes: [Node] }

    public var id: String
    public var published: Date?
    public var summary: String
    public var score: Double?
    public var severity: String?
    public var vector: String?
    public var kevAdded: String?
    public var configs: [Config]
    public var references: [String]
}

public enum Applicability: Equatable { case affected, affectedUnbounded, notAffected }

/// NVD CVE API 2.0. Without an API key NVD allows 5 requests per 30 seconds, so requests are
/// spaced out and results are cached for a day per product+version.
public actor NVDClient {
    let apiKey: String?
    let offline: Bool
    var last = Date.distantPast
    let cache = DiskCache("nvd")
    public private(set) var requests = 0
    public private(set) var errors: [String] = []

    public init(apiKey: String?, offline: Bool) {
        self.apiKey = (apiKey?.trimmed.isEmpty ?? true) ? nil : apiKey?.trimmed
        self.offline = offline
    }

    var spacing: TimeInterval { apiKey == nil ? 6.2 : 0.7 }

    func fetch(_ url: String) async throws -> Data {
        var attempt = 0
        while true {
            let wait = spacing - Date().timeIntervalSince(last)
            if wait > 0 { try? await Task.sleep(nanoseconds: UInt64(wait * 1e9)) }
            last = Date(); requests += 1
            do {
                return try await HTTP.get(url, headers: apiKey.map { ["apiKey": $0] } ?? [:])
            } catch let e as HTTPError where (e.status == 403 || e.status == 429 || e.status == 503) && attempt < 2 {
                attempt += 1
                try? await Task.sleep(nanoseconds: 30_000_000_000)   // rate-limited: back off a full window
            }
        }
    }

    /// Every CVE whose applicability statement matches `cpe:2.3:<part>:<vendor>:<product>:<version>`.
    /// With `version: nil`, the product's CVEs that are in CISA's KEV catalog (any version).
    public func cves(part: String, vendor: String, product: String, version: String?) async -> [NVDCve]? {
        let ver = version.map(NVDClient.cpeVersion)
        let match = "cpe:2.3:\(part):\(vendor):\(product)" + (ver.map { ":\($0)" } ?? "")
        let key = "vm-\(part)-\(vendor)-\(product)-\(ver ?? "KEV").json"
        if let c = cache.get(key, [NVDCve].self, maxAge: offline ? nil : 86400) { return c }
        if offline { return nil }
        var all: [NVDCve] = []
        var start = 0
        do {
            repeat {
                let url = "https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected\(ver == nil ? "&hasKev" : "")&resultsPerPage=2000&startIndex=\(start)&virtualMatchString="
                    + (match.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? match)
                let d = try await fetch(url)
                guard let j = jsonObject(d) as? [String: Any] else { break }
                let total = j["totalResults"] as? Int ?? 0
                let rows = j["vulnerabilities"] as? [[String: Any]] ?? []
                all += rows.compactMap { ($0["cve"] as? [String: Any]).map(NVDClient.reduce) }
                start += rows.count
                if rows.isEmpty || start >= total { break }
            } while true
        } catch {
            errors.append("\(vendor):\(product) — \(error)")
            return cache.get(key, [NVDCve].self)   // stale copy beats nothing
        }
        cache.put(key, all)
        return all
    }

    /// One CVE by id (cached for a week; used to check new KEV entries NVD didn't return).
    public func cve(_ id: String) async -> NVDCve? {
        let key = "cve-\(id).json"
        if let c = cache.get(key, NVDCve.self, maxAge: offline ? nil : 7 * 86400) { return c }
        if offline { return nil }
        guard let d = try? await fetch("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=\(id)"),
              let j = jsonObject(d) as? [String: Any],
              let c = ((j["vulnerabilities"] as? [[String: Any]])?.first?["cve"] as? [String: Any]).map(NVDClient.reduce) else { return nil }
        cache.put(key, c)
        return c
    }

    /// CPE-safe version: first run of version characters ("6.2.5 (43380)" → "6.2.5").
    public static func cpeVersion(_ v: String) -> String {
        (v.firstMatch(#"[0-9][0-9A-Za-z._-]*"#)?.first ?? v).lowercased()
    }

    static func reduce(_ c: [String: Any]) -> NVDCve {
        let desc = (c["descriptions"] as? [[String: Any]] ?? []).first { ($0["lang"] as? String) == "en" }?["value"] as? String ?? ""
        var score: Double?, sev: String?, vec: String?
        let metrics = c["metrics"] as? [String: Any] ?? [:]
        for k in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"] {
            guard let list = metrics[k] as? [[String: Any]], !list.isEmpty else { continue }
            let m = list.first { ($0["type"] as? String) == "Primary" } ?? list[0]
            let data = m["cvssData"] as? [String: Any] ?? [:]
            score = data["baseScore"] as? Double
            sev = (data["baseSeverity"] as? String) ?? (m["baseSeverity"] as? String)
            vec = data["vectorString"] as? String
            break
        }
        let configs: [NVDCve.Config] = (c["configurations"] as? [[String: Any]] ?? []).map { cfg in
            NVDCve.Config(op: cfg["operator"] as? String ?? "OR", nodes: (cfg["nodes"] as? [[String: Any]] ?? []).map { n in
                NVDCve.Node(op: n["operator"] as? String ?? "OR", negate: n["negate"] as? Bool ?? false,
                            matches: (n["cpeMatch"] as? [[String: Any]] ?? []).map { m in
                    NVDCve.Match(vulnerable: m["vulnerable"] as? Bool ?? true, criteria: m["criteria"] as? String ?? "",
                                 vsi: m["versionStartIncluding"] as? String, vse: m["versionStartExcluding"] as? String,
                                 vei: m["versionEndIncluding"] as? String, vee: m["versionEndExcluding"] as? String)
                })
            })
        }
        let refs = (c["references"] as? [[String: Any]] ?? []).compactMap { $0["url"] as? String }
        return NVDCve(id: c["id"] as? String ?? "?", published: parseDate(c["published"] as? String), summary: String(desc.prefix(600)),
                      score: score, severity: sev, vector: vec, kevAdded: c["cisaExploitAdd"] as? String, configs: configs, references: Array(refs.prefix(10)))
    }

    // MARK: applicability

    static let macTargets: Set<String> = ["*", "-", "macos", "mac_os", "mac_os_x", "macos_x", "os_x", "osx", "mac"]
    static let macOSProducts: Set<String> = ["macos", "mac_os_x", "mac_os", "macos_server", "mac_os_x_server"]

    /// Does this CVE's applicability statement cover `vendor:product` at `version`, on a Mac?
    public static func evaluate(_ cve: NVDCve, part: String, vendor: String, product: String, version: String) -> Applicability {
        var unbounded = false
        func matches(_ m: NVDCve.Match) -> Bool {
            let f = m.criteria.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            guard f.count >= 6 else { return false }
            let (mp, mv, mprod, mver) = (f[2], f[3], f[4], f[5])
            if mp == part && mv == vendor && mprod == product {
                guard m.vulnerable else { return false }
                if f.count > 10, !macTargets.contains(f[10]) { return false }   // target_sw: windows, android, …
                let hasRange = m.vsi != nil || m.vse != nil || m.vei != nil || m.vee != nil
                if mver != "*" && mver != "-" {
                    return Version.compare(version, mver.replacingOccurrences(of: "\\", with: "")) == 0
                }
                if !hasRange { unbounded = true; return true }
                if let s = m.vsi, Version.compare(version, s) < 0 { return false }
                if let s = m.vse, Version.compare(version, s) <= 0 { return false }
                if let e = m.vei, Version.compare(version, e) > 0 { return false }
                if let e = m.vee, Version.compare(version, e) >= 0 { return false }
                return true
            }
            // "Running on" platforms: only a Mac counts.
            if mp == "o" { return mv == "apple" && macOSProducts.contains(mprod) }
            return false
        }
        func node(_ n: NVDCve.Node) -> Bool {
            let r = n.op == "AND" ? n.matches.allSatisfy(matches) : n.matches.contains(where: matches)
            return n.negate ? !r : r
        }
        for c in cve.configs {
            let ok = c.op == "AND" ? (!c.nodes.isEmpty && c.nodes.allSatisfy(node)) : c.nodes.contains(where: node)
            if ok { return unbounded ? .affectedUnbounded : .affected }
            unbounded = false
        }
        return .notAffected
    }

    public static func vulnerability(_ c: NVDCve, confidence: Confidence = .versionMatch) -> Vulnerability {
        var v = Vulnerability(id: c.id)
        v.summary = c.summary
        v.cvss = c.score
        v.vector = c.vector
        v.severity = c.score.map(Severity.init(score:)) ?? c.severity.map(Severity.init(label:)) ?? .unknown
        v.published = c.published
        v.references = c.references
        v.source = "NVD"
        v.confidence = confidence
        return v
    }
}
