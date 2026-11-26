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
            case (.word(let w)?, nil): return postWords.contains(w) ? 1 : -1   // 1.0b < 1.0 < 1.0p1
            case (nil, .word(let w)?): return postWords.contains(w) ? -1 : 1
            case (nil, nil): return 0
            }
        }
        return 0
    }

    public static func less(_ a: String, _ b: String) -> Bool { compare(a, b) < 0 }

    /// Words that mark a release *after* the one they follow (OpenSSH "9.8p1", "1.0.post1").
    static let postWords: Set<String> = ["post", "patch", "pl", "p", "rev"]

    /// Compare using the package's own ecosystem rules where they differ from the loose order:
    /// PEP 440 for Python, SemVer for npm, cargo and Go. Everything else uses `compare`.
    public static func compare(_ a: String, _ b: String, in ecosystem: Ecosystem) -> Int {
        switch ecosystem {
        case .pypi: return PEP440.compare(a, b) ?? compare(a, b)
        case .npm, .crates, .go: return SemVer.compare(a, b) ?? compare(a, b)
        default: return compare(a, b)
        }
    }

    public static func less(_ a: String, _ b: String, in ecosystem: Ecosystem) -> Bool { compare(a, b, in: ecosystem) < 0 }

    /// Same rules, keyed by an OSV ecosystem name ("PyPI", "npm", "crates.io", "Go", "GIT"…).
    public static func compare(_ a: String, _ b: String, osvEcosystem: String) -> Int {
        let e = Ecosystem.allCases.first { $0.osvName == osvEcosystem }
        return e.map { compare(a, b, in: $0) } ?? compare(a, b)
    }

    /// PEP 440: [N!]N(.N)*[{a|b|rc}N][.postN][.devN][+local]. Order is
    /// dev < pre < release < post; local labels only break ties.
    enum PEP440 {
        struct Parsed { var epoch: Int; var release: [Int]; var pre: (Int, Int)?; var post: Int?; var dev: Int?; var local: String }

        static func parse(_ raw: String) -> Parsed? {
            var v = raw.trimmed.lowercased()
            if v.hasPrefix("v") { v.removeFirst() }
            let rx = #"^(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|alpha|b|beta|c|rc|pre|preview)[-_.]?(\d*))?(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d*))?(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+([a-z0-9._-]+))?$"#
            guard let m = v.firstMatch(rx) else { return nil }
            let rel = m[2].split(separator: ".").map { Int($0.prefix(18)) ?? 0 }
            var pre: (Int, Int)?
            if !m[3].isEmpty {
                let rank: Int
                switch m[3] { case "a", "alpha": rank = 0; case "b", "beta": rank = 1; default: rank = 2 }
                pre = (rank, Int(m[4]) ?? 0)
            }
            var post: Int?
            if !m[5].isEmpty { post = Int(m[5]) ?? 0 } else if !m[6].isEmpty { post = Int(m[7]) ?? 0 }
            let dev: Int? = m[8].isEmpty ? nil : (Int(m[9]) ?? 0)
            return Parsed(epoch: Int(m[1]) ?? 0, release: rel, pre: pre, post: post, dev: dev, local: m[10])
        }

        static func compare(_ a: String, _ b: String) -> Int? {
            guard let x = parse(a), let y = parse(b) else { return nil }
            func c<T: Comparable>(_ p: T, _ q: T) -> Int { p < q ? -1 : p > q ? 1 : 0 }
            if x.epoch != y.epoch { return c(x.epoch, y.epoch) }
            let n = max(x.release.count, y.release.count)
            for i in 0..<n {
                let p = i < x.release.count ? x.release[i] : 0, q = i < y.release.count ? y.release[i] : 0
                if p != q { return c(p, q) }
            }
            // A bare dev release ("1.0.dev1") sorts before every pre-release of 1.0.
            func preKey(_ v: Parsed) -> (Int, Int) {
                if let pre = v.pre { return pre }
                if v.dev != nil && v.post == nil { return (-1, 0) }
                return (3, 0)
            }
            let (pa, pb) = (preKey(x), preKey(y))
            if pa != pb { return pa < pb ? -1 : 1 }
            let (qa, qb) = (x.post ?? -1, y.post ?? -1)
            if qa != qb { return c(qa, qb) }
            let (da, db) = (x.dev ?? Int.max, y.dev ?? Int.max)
            if da != db { return c(da, db) }
            if x.local != y.local { return x.local.isEmpty ? -1 : y.local.isEmpty ? 1 : Version.compare(x.local, y.local) }
            return 0
        }
    }

    /// SemVer 2.0: MAJOR.MINOR.PATCH[-prerelease][+build]. Build metadata never affects order;
    /// a pre-release sorts before its release; Go's "+incompatible" is build metadata too.
    enum SemVer {
        static func parse(_ raw: String) -> (core: [Int], pre: [String])? {
            var v = raw.trimmed
            if v.hasPrefix("v") || v.hasPrefix("=") { v.removeFirst() }
            if let plus = v.firstIndex(of: "+") { v = String(v[..<plus]) }
            var pre: [String] = []
            if let dash = v.firstIndex(of: "-") {
                pre = v[v.index(after: dash)...].split(separator: ".", omittingEmptySubsequences: false).map(String.init)
                v = String(v[..<dash])
            }
            let parts = v.split(separator: ".", omittingEmptySubsequences: false)
            guard (1...4).contains(parts.count) else { return nil }
            var core: [Int] = []
            for p in parts { guard !p.isEmpty, p.allSatisfy({ $0.isASCII && $0.isNumber }), let n = Int(p.prefix(18)) else { return nil }; core.append(n) }
            return (core, pre)
        }

        static func compare(_ a: String, _ b: String) -> Int? {
            guard let x = parse(a), let y = parse(b) else { return nil }
            for i in 0..<max(x.core.count, y.core.count) {
                let p = i < x.core.count ? x.core[i] : 0, q = i < y.core.count ? y.core[i] : 0
                if p != q { return p < q ? -1 : 1 }
            }
            switch (x.pre.isEmpty, y.pre.isEmpty) {
            case (true, true): return 0
            case (true, false): return 1
            case (false, true): return -1
            default: break
            }
            for i in 0..<max(x.pre.count, y.pre.count) {
                guard i < x.pre.count else { return -1 }
                guard i < y.pre.count else { return 1 }
                let (p, q) = (x.pre[i], y.pre[i])
                switch (Int(p), Int(q)) {
                case let (m?, n?): if m != n { return m < n ? -1 : 1 }
                case (_?, nil): return -1          // numeric identifiers sort before alphanumeric
                case (nil, _?): return 1
                default: if p != q { return p < q ? -1 : 1 }
                }
            }
            return 0
        }
    }

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
