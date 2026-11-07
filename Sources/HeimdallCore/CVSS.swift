import Foundation

/// CVSS v3.0/v3.1 base score from a vector string (FIRST specification, section 7).
public enum CVSS {
    public static func baseScore(_ vector: String) -> Double? {
        guard vector.hasPrefix("CVSS:3") else { return nil }
        var m: [String: String] = [:]
        for part in vector.split(separator: "/").dropFirst() {
            let kv = part.split(separator: ":", maxSplits: 1)
            if kv.count == 2 { m[String(kv[0])] = String(kv[1]) }
        }
        guard let av = ["N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2][m["AV"] ?? ""],
              let ac = ["L": 0.77, "H": 0.44][m["AC"] ?? ""],
              let ui = ["N": 0.85, "R": 0.62][m["UI"] ?? ""],
              let s = m["S"], s == "U" || s == "C",
              let c = cia(m["C"]), let i = cia(m["I"]), let a = cia(m["A"]) else { return nil }
        let changed = s == "C"
        let pr: Double
        switch m["PR"] {
        case "N": pr = 0.85
        case "L": pr = changed ? 0.68 : 0.62
        case "H": pr = changed ? 0.5 : 0.27
        default: return nil
        }
        let iss = 1 - (1 - c) * (1 - i) * (1 - a)
        let impact = changed ? 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15) : 6.42 * iss
        let exploit = 8.22 * av * ac * pr * ui
        if impact <= 0 { return 0 }
        return roundUp(min((changed ? 1.08 : 1) * (impact + exploit), 10))
    }

    private static func cia(_ v: String?) -> Double? { ["H": 0.56, "L": 0.22, "N": 0][v ?? ""] }

    static func roundUp(_ x: Double) -> Double {
        let i = Int((x * 100_000).rounded())
        if i % 10_000 == 0 { return Double(i) / 100_000 }
        return (floor(Double(i) / 10_000) + 1) / 10
    }
}
