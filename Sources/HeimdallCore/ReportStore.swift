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
    public var isEmpty: Bool { appeared.isEmpty && resolved.isEmpty }

    static func key(_ f: Finding, _ v: Vulnerability) -> String { "\(f.package.ecosystem.rawValue)|\(f.package.parent ?? "")|\(f.package.name)|\(v.headlineID)" }

    public init(current: ScanReport, previous: ScanReport?) {
        guard let previous else { return }
        let now = Dictionary(current.allVulns.map { (Self.key($0.0, $0.1), $0) }, uniquingKeysWith: { a, _ in a })
        let then = Dictionary(previous.allVulns.map { (Self.key($0.0, $0.1), $0) }, uniquingKeysWith: { a, _ in a })
        let byPriority: ((Finding, Vulnerability), (Finding, Vulnerability)) -> Bool = { a, b in a.1.priority > b.1.priority }
        appeared = now.filter { then[$0.key] == nil }.map { $0.value }.sorted(by: byPriority)
        resolved = then.filter { now[$0.key] == nil }.map { $0.value }.sorted(by: byPriority)
    }
}

public enum ReportExport {
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
        var lines = ["ecosystem,package,version,parent,location,vulnerability,aliases,severity,cvss,epss,kev,kev_added,ransomware,fixed,confidence,source,fix,summary"]
        for (f, v) in r.allVulns.sorted(by: { (a: (Finding, Vulnerability), b: (Finding, Vulnerability)) in a.1.priority > b.1.priority }) {
            let p = f.package
            let others = ([v.id] + v.aliases).filter { $0 != v.headlineID }.joined(separator: " ")
            let cvss = v.cvss.map { String(format: "%.1f", $0) } ?? ""
            let epss = v.epss.map { String(format: "%.4f", $0) } ?? ""
            var row: [String] = [p.ecosystem.rawValue, p.name, p.version, p.parent ?? "", p.location, v.headlineID, others, v.severity.rawValue, cvss, epss]
            row += [v.isKEV ? "yes" : "", v.kev?.dateAdded ?? "", v.kev?.ransomware == true ? "yes" : ""]
            row += [v.fixed.joined(separator: " "), v.confidence.rawValue, v.source, f.fixHint, v.summary]
            lines.append(row.map(q).joined(separator: ","))
        }
        return lines.joined(separator: "\n") + "\n"
    }
}
