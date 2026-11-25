import Foundation

/// Loose version comparison that works across ecosystems: numbers compare numerically,
/// words compare alphabetically, and a trailing word ("1.0b1", "2.0-rc1") ranks below the
/// release it precedes.
public enum Version {
    enum Token: Equatable { case num(Int), word(String) }

    static func tokens(_ v: String) -> [Token] {
        var out: [Token] = []
        var cur = ""; var isNum = false
        func flush() {
            guard !cur.isEmpty else { return }
            out.append(isNum ? .num(Int(cur.prefix(18)) ?? 0) : .word(cur.lowercased()))
            cur = ""
        }
        for ch in v.trimmingCharacters(in: .whitespaces) {
            if ch.isASCII && ch.isNumber {
                if !isNum { flush(); isNum = true }
                cur.append(ch)
            } else if ch.isLetter {
                if isNum { flush(); isNum = false }
                cur.append(ch)
            } else {
                flush(); isNum = false
            }
        }
        flush()
        return out
    }

    /// -1, 0, 1
    public static func compare(_ a: String, _ b: String) -> Int {
        var x = tokens(a), y = tokens(b)
        // Strip a leading "v" ("v1.2.3").
        if case .word("v") = x.first { x.removeFirst() }
        if case .word("v") = y.first { y.removeFirst() }
        let n = max(x.count, y.count)
        for i in 0..<n {
            switch (i < x.count ? x[i] : nil, i < y.count ? y[i] : nil) {
            case let (.num(p)?, .num(q)?): if p != q { return p < q ? -1 : 1 }
            case let (.word(p)?, .word(q)?): if p != q { return p < q ? -1 : 1 }
            case (.num?, .word?): return 1      // 1.0.1 > 1.0rc
            case (.word?, .num?): return -1
            case (.num(let p)?, nil): if p != 0 || x[i...].contains(where: { if case .num(let z) = $0 { return z != 0 }; return false }) { return 1 }
            case (nil, .num(let q)?): if q != 0 || y[i...].contains(where: { if case .num(let z) = $0 { return z != 0 }; return false }) { return -1 }
            case (.word?, nil): return -1       // 1.0b < 1.0
            case (nil, .word?): return 1
            case (nil, nil): return 0
            }
        }
        return 0
    }

    public static func less(_ a: String, _ b: String) -> Bool { compare(a, b) < 0 }

    /// Compare two Homebrew bottle/keg tags: upstream version first, then the `_N` revision
    /// (missing = 0). A `-N` bottle rebuild suffix is ignored — same package, rebuilt.
    /// `compare` alone reads "1.11.1_7" as newer than "1.11.1" only by accident of parsing and
    /// never knows the revision is what is installed, which is how a current keg showed up as
    /// 721 days behind.
    public static func compareBrew(_ a: String, _ b: String) -> Int {
        func split(_ t: String) -> (String, Int) {
            let noRebuild = t.components(separatedBy: "-").first ?? t
            let parts = noRebuild.components(separatedBy: "_")
            return (parts[0], parts.count > 1 ? Int(parts[1]) ?? 0 : 0)
        }
        let (va, ra) = split(a), (vb, rb) = split(b)
        let c = compare(va, vb)
        return c != 0 ? c : (ra < rb ? -1 : ra > rb ? 1 : 0)
    }

    /// Homebrew keg versions carry a revision suffix ("3.2.1_1").
    public static func stripBrewRevision(_ v: String) -> String {
        if let r = v.range(of: #"_\d+$"#, options: .regularExpression) { return String(v[..<r.lowerBound]) }
        return v
    }
}
