import Foundation

/// Keeps the latest report and the one before it, so each edition can say what changed.
public enum ReportStore {
    static var latestURL: URL { Paths.support.appendingPathComponent("latest.json") }
    static var previousURL: URL { Paths.support.appendingPathComponent("previous.json") }

    public static func save(_ r: ScanReport) {
        let fm = FileManager.default
        if fm.fileExists(atPath: latestURL.path) {
            try? fm.removeItem(at: previousURL)
            try? fm.moveItem(at: latestURL, to: previousURL)
        }
        if let d = try? JSONCoding.encoder.encode(r) { try? d.write(to: latestURL, options: .atomic) }
    }
    public static func latest() -> ScanReport? { load(latestURL) }
    public static func previous() -> ScanReport? { load(previousURL) }
    static func load(_ u: URL) -> ScanReport? { (try? Data(contentsOf: u)).flatMap { try? JSONCoding.decoder.decode(ScanReport.self, from: $0) } }
}

public struct Changes: Sendable {
    public var appeared: [(Finding, Vulnerability)] = []
    public var resolved: [(Finding, Vulnerability)] = []
    public var unverified: [(Finding, Vulnerability)] = []
    public var outcomes: [String: RemediationOutcome] = [:]
    public var isEmpty: Bool { appeared.isEmpty && resolved.isEmpty && unverified.isEmpty }
    public func outcome(_ f: Finding, _ v: Vulnerability) -> RemediationOutcome? { outcomes[Self.key(f, v)] }

    static func key(_ f: Finding, _ v: Vulnerability) -> String { "\(f.package.installationKey)|\(v.headlineID)" }

    public init(current: ScanReport, previous: ScanReport?) {
        guard let previous, !current.partial else { return }
        let now = Dictionary(current.allVulns.map { (Self.key($0.0, $0.1), $0) }, uniquingKeysWith: { a, _ in a })
        let then = Dictionary(previous.allVulns.map { (Self.key($0.0, $0.1), $0) }, uniquingKeysWith: { a, _ in a })
        let byPriority: ((Finding, Vulnerability), (Finding, Vulnerability)) -> Bool = { a, b in a.1.priority > b.1.priority }
        appeared = now.filter { then[$0.key] == nil }.map { $0.value }.sorted(by: byPriority)
        for (key, pair) in then where now[key] == nil {
            let outcome = RemediationOutcome.assess(pair.0.package, in: current, previous: previous)
            outcomes[key] = outcome
            if outcome == .fixed || outcome == .removed { resolved.append(pair) }
            else { unverified.append(pair) }
        }
        resolved.sort(by: byPriority)
        unverified.sort(by: byPriority)
    }
}

public enum ReportExport {
    /// CycloneDX 1.5 JSON: every package as a component (with a purl where the ecosystem has one)
    /// and every advisory as a vulnerability that names the components it affects. KEV and EPSS
    /// travel as properties, so other tools keep the signals Heimdall ranks by.
    public static func cycloneDX(_ r: ScanReport, serial: UUID = UUID()) -> Data {
        let iso = ISO8601DateFormatter()
        var refs: [String: String] = [:]
        var components: [[String: Any]] = []
        for (i, p) in r.packages.enumerated() {
            let ref = "pkg-\(i)"
            refs[p.id] = ref
            var c: [String: Any] = ["bom-ref": ref, "type": componentType(p), "name": p.name, "version": p.version]
            if let purl = purl(p) { c["purl"] = purl }
            if let g = group(p) { c["group"] = g }
            var props: [[String: String]] = [["name": "heimdall:ecosystem", "value": p.ecosystem.rawValue]]
            if !p.location.isEmpty { props.append(["name": "heimdall:location", "value": p.location]) }
            if let parent = p.parent { props.append(["name": "heimdall:bundledIn", "value": parent]) }
            if let b = p.bundleID { props.append(["name": "heimdall:bundleID", "value": b]) }
            if let e = p.exposure, e.any { props.append(["name": "heimdall:exposure", "value": e.summary]) }
            if let m = p.maintenance { props.append(["name": "heimdall:maintenance", "value": m.state.rawValue]) }
            c["properties"] = props
            components.append(c)
        }

        // One entry per advisory, listing every installed component it applies to.
        var order: [String] = []
        var byID: [String: (Vulnerability, [String])] = [:]
        for (f, v) in r.allVulns {
            guard let ref = refs[f.package.id] else { continue }
            let key = v.headlineID
            if byID[key] == nil { order.append(key); byID[key] = (v, []) }
            if !byID[key]!.1.contains(ref) { byID[key]!.1.append(ref) }
        }
        let vulns: [[String: Any]] = order.compactMap { key in
            guard let (v, affected) = byID[key] else { return nil }
            var e: [String: Any] = ["bom-ref": "vuln-" + key, "id": key, "source": ["name": v.source.isEmpty ? "Heimdall" : v.source]]
            if !v.summary.isEmpty { e["description"] = v.summary }
            var rating: [String: Any] = ["severity": v.severity == .unknown ? "unknown" : v.severity.rawValue]
            if let s = v.cvss { rating["score"] = s; rating["method"] = (v.vector ?? "").hasPrefix("CVSS:4") ? "CVSSv4" : (v.vector ?? "").hasPrefix("CVSS:3") ? "CVSSv31" : "other" }
            if let vec = v.vector { rating["vector"] = vec }
            e["ratings"] = [rating]
            if let d = v.published { e["published"] = iso.string(from: d) }
            let others = v.aliases.filter { $0 != key }
            if !others.isEmpty { e["references"] = others.map { ["id": $0, "source": ["name": $0.hasPrefix("CVE-") ? "NVD" : "OSV"]] } }
            if !v.fixed.isEmpty { e["recommendation"] = "Fixed in " + v.fixed.joined(separator: ", ") }
            e["affects"] = affected.map { ["ref": $0] }
            var props: [[String: String]] = []
            if let k = v.kev {
                props.append(["name": "heimdall:kev", "value": k.listName])
                props.append(["name": "heimdall:kevDateAdded", "value": k.dateAdded])
                if k.ransomware { props.append(["name": "heimdall:ransomware", "value": "known"]) }
            }
            if let p = v.epss { props.append(["name": "heimdall:epss", "value": String(format: "%.5f", p)]) }
            if v.hasPublicExploit { props.append(["name": "heimdall:publicExploit", "value": (v.publicExploits ?? []).joined(separator: ", ")]) }
            if !props.isEmpty { e["properties"] = props }
            return e
        }

        let host: [String: Any] = ["type": "device", "name": r.posture.hostName.isEmpty ? "Mac" : r.posture.hostName,
                                   "version": r.posture.osVersion, "bom-ref": "host"]
        let doc: [String: Any] = [
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "serialNumber": "urn:uuid:" + serial.uuidString.lowercased(),
            "metadata": ["timestamp": iso.string(from: r.generated), "component": host,
                         "tools": ["components": [["type": "application", "name": "Heimdall"]]]],
            "components": components,
            "vulnerabilities": vulns,
        ]
        return (try? JSONSerialization.data(withJSONObject: doc, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])) ?? Data()
    }

    static func componentType(_ p: Package) -> String {
        switch p.ecosystem {
        case .macos: return "operating-system"
        case .app, .cask: return "application"
        case .browserExtension: return "application"
        default: return "library"
        }
    }

    static func group(_ p: Package) -> String? {
        guard p.ecosystem == .npm, p.name.hasPrefix("@"), let slash = p.name.firstIndex(of: "/") else { return nil }
        return String(p.name[..<slash])
    }

    /// Package URL (purl-spec) for ecosystems that have a registered type.
    static func purl(_ p: Package) -> String? {
        func enc(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-._~"))) ?? s }
        let v = "@" + enc(p.version)
        switch p.ecosystem {
        case .pypi: return "pkg:pypi/" + enc(LanguageCollector.pep503(p.name)) + v
        case .npm:
            if let g = group(p) { return "pkg:npm/" + enc(g) + "/" + enc(String(p.name.dropFirst(g.count + 1))) + v }
            return "pkg:npm/" + enc(p.name) + v
        case .crates: return "pkg:cargo/" + enc(p.name) + v
        case .rubygems: return "pkg:gem/" + enc(p.name) + v
        case .go: return "pkg:golang/" + p.name.split(separator: "/").map { enc(String($0)) }.joined(separator: "/") + v
        case .homebrew: return "pkg:generic/homebrew/" + enc(p.name) + v
        case .cask: return "pkg:generic/homebrew-cask/" + enc(p.cask ?? p.name) + v
        default: return nil
        }
    }

    public static func json(_ r: ScanReport) -> Data { (try? JSONCoding.pretty.encode(r)) ?? Data() }

    public static func csv(_ r: ScanReport) -> String {
        func q(_ raw: String) -> String {
            // CSV quoting alone does not stop spreadsheet formula interpretation.
            let leading = raw.drop(while: { $0.isWhitespace })
            let unsafe = leading.first.map { "=+-@".contains($0) } == true
                || raw.unicodeScalars.first.map { CharacterSet(charactersIn: "\t\r\n").contains($0) } == true
            let s = unsafe ? "'" + raw : raw
            return s.unicodeScalars.contains(where: { CharacterSet(charactersIn: ",\"\r\n").contains($0) })
                ? "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\"" : s
        }
        var lines = ["ecosystem,package,version,parent,location,vulnerability,aliases,severity,cvss,epss,kev,kev_added,ransomware,fixed,confidence,source,running,listening,autostart,first_seen,age_days,maintenance,maintenance_reason,coverage,coverage_detail,fix,summary"]
        for (f, v) in r.allVulns.sorted(by: { (a: (Finding, Vulnerability), b: (Finding, Vulnerability)) in a.1.priority > b.1.priority }) {
            let p = f.package
            let others = ([v.id] + v.aliases).filter { $0 != v.headlineID }.joined(separator: " ")
            let cvss = v.cvss.map { String(format: "%.1f", $0) } ?? ""
            let epss = v.epss.map { String(format: "%.4f", $0) } ?? ""
            var row: [String] = [p.ecosystem.rawValue, p.name, p.version, p.parent ?? "", p.location, v.headlineID, others, v.severity.rawValue, cvss, epss]
            row += [v.isKEV ? "yes" : "", v.kev?.dateAdded ?? "", v.kev?.ransomware == true ? "yes" : ""]
            row += [v.fixed.joined(separator: " "), v.confidence.rawValue, v.source]
            let e = p.exposure
            row += [e.map { $0.running ? "yes" : "no" } ?? "", e.map { $0.ports.map(String.init).joined(separator: " ") } ?? "",
                    e.map { $0.autostart ? "yes" : "no" } ?? ""]
            row += [f.firstSeen.map { ISO8601DateFormatter().string(from: $0) } ?? "", f.ageDays.map(String.init) ?? ""]
            row += [p.maintenance?.state.rawValue ?? "", p.maintenance?.reason ?? ""]
            row += [p.coverage?.state.rawValue ?? "unknown", p.coverage?.detail ?? ""]
            row += [f.fixHint, v.summary]
            lines.append(row.map(q).joined(separator: ","))
        }
        return lines.joined(separator: "\n") + "\n"
    }
}
