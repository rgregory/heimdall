import Foundation

public struct LanguageOptions: Codable, Sendable, Equatable {
    public var python = true
    public var npm = true
    public var npmNested = false
    public var cargo = true
    public var gems = true
    public var go = true
    /// Also read Go build info from binaries in Homebrew's bin (many formulae are Go programs).
    public var goInHomebrew = false
    /// Extra virtualenvs / site-packages / node_modules / bin folders the user wants checked.
    public var extraPythonRoots: [String] = []
    public var extraGoRoots: [String] = []
    public init() {}
}

/// Language package managers, read straight from their metadata on disk (no interpreter runs,
/// so nothing prompts for Xcode tools and nothing executes package code).
public enum LanguageCollector {
    public static func collect(_ o: LanguageOptions) -> CollectorOutput {
        var out = CollectorOutput()
        if o.python { let p = python(extra: o.extraPythonRoots); out.packages += p; out.status.append(status("Python", p, "dist-info metadata in site-packages (system, Homebrew, user, pipx, uv, pyenv, conda)")) }
        if o.npm { let p = npm(nested: o.npmNested); out.packages += p; out.status.append(status("npm (global)", p, "package.json in global node_modules\(o.npmNested ? ", including dependencies" : "")")) }
        if o.cargo { let p = cargo(); out.packages += p; out.status.append(status("cargo", p, "~/.cargo/.crates2.json")) }
        if o.gems { let p = gems(); out.packages += p; out.status.append(status("Ruby gems", p, "gem specifications outside /System")) }
        if o.go {
            var roots = ["~/go/bin", ProcessInfo.processInfo.environment["GOBIN"] ?? ""].filter { !$0.isEmpty } + o.extraGoRoots
            if o.goInHomebrew { roots += ["/opt/homebrew/bin", "/usr/local/bin"] }
            let p = goBinaries(roots: roots)
            out.packages += p
            out.status.append(status("Go binaries", p, "embedded build info in \(roots.joined(separator: ", "))"))
        }
        return out
    }

    static func status(_ name: String, _ p: [Package], _ detail: String) -> SourceStatus {
        SourceStatus(name: name, state: p.isEmpty ? .skipped : .ok, detail: p.isEmpty ? "nothing found — \(detail)" : detail, count: p.count, updated: Date())
    }

    // MARK: Python

    static let pythonPatterns = [
        "/opt/homebrew/lib/python3*/site-packages", "/usr/local/lib/python3*/site-packages",
        "/opt/homebrew/Cellar/*/*/libexec/lib/python3*/site-packages", "/usr/local/Cellar/*/*/libexec/lib/python3*/site-packages",
        "~/Library/Python/3*/lib/python/site-packages",
        "/Library/Frameworks/Python.framework/Versions/*/lib/python3*/site-packages",
        "~/.pyenv/versions/*/lib/python3*/site-packages",
        "~/.local/pipx/venvs/*/lib/python3*/site-packages", "~/.local/share/pipx/venvs/*/lib/python3*/site-packages",
        "~/.local/share/uv/tools/*/lib/python3*/site-packages",
        "~/miniconda3/lib/python3*/site-packages", "~/anaconda3/lib/python3*/site-packages", "~/miniforge3/lib/python3*/site-packages",
        "/opt/homebrew/Caskroom/miniconda/base/lib/python3*/site-packages",
    ]

    static func python(extra: [String]) -> [Package] {
        var dirs = pythonPatterns.flatMap(FS.glob)
        for e in extra.map(Paths.expand) {
            dirs += e.hasSuffix("site-packages") ? [e] : FS.glob(e + "/lib/python3*/site-packages")
        }
        var pkgs: [Package] = [], seen = Set<String>()
        for dir in dirs.map(FS.resolve).uniqued() {
            let ctx = pythonContext(dir)
            for e in FS.list(dir) {
                let meta: String
                if e.hasSuffix(".dist-info") { meta = "\(dir)/\(e)/METADATA" }
                else if e.hasSuffix(".egg-info") { meta = FS.isDir("\(dir)/\(e)") ? "\(dir)/\(e)/PKG-INFO" : "\(dir)/\(e)" }
                else { continue }
                guard let (name, ver) = readMetadata(meta) else { continue }
                let key = "\(dir)|\(pep503(name))|\(ver)"
                guard seen.insert(key).inserted else { continue }
                var p = Package(ecosystem: .pypi, name: name, version: ver, location: dir, source: ctx.label)
                p.parent = ctx.parent
                pkgs.append(p)
            }
        }
        return pkgs
    }

    static func readMetadata(_ path: String) -> (String, String)? {
        guard let h = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? h.close() }
        let head = String(decoding: h.readData(ofLength: 4096), as: UTF8.self)
        var name: String?, ver: String?
        for line in head.split(separator: "\n", omittingEmptySubsequences: false) {
            if line.isEmpty { break }      // headers end at the first blank line
            if name == nil, line.hasPrefix("Name:") { name = line.dropFirst(5).trimmingCharacters(in: .whitespaces) }
            if ver == nil, line.hasPrefix("Version:") { ver = line.dropFirst(8).trimmingCharacters(in: .whitespaces) }
        }
        guard let name, let ver, !name.isEmpty, !ver.isEmpty else { return nil }
        return (name, ver)
    }

    /// PEP 503 name normalisation, which is what OSV keys PyPI packages on.
    public static func pep503(_ n: String) -> String {
        n.lowercased().replacingOccurrences(of: #"[-_.]+"#, with: "-", options: .regularExpression)
    }

    static func pythonContext(_ dir: String) -> (label: String, parent: String?) {
        if let m = dir.firstMatch(#"/pipx/venvs/([^/]+)/"#) { return ("pipx app \(m[1])", m[1]) }
        if let m = dir.firstMatch(#"/uv/tools/([^/]+)/"#) { return ("uv tool \(m[1])", m[1]) }
        if let m = dir.firstMatch(#"/Cellar/([^/]+)/[^/]+/libexec/"#) { return ("vendored by Homebrew formula \(m[1])", m[1]) }
        if let m = dir.firstMatch(#"/\.pyenv/versions/([^/]+)/"#) { return ("pyenv \(m[1])", nil) }
        if dir.contains("/Library/Python/") { return ("user site-packages", nil) }
        if dir.contains("conda") || dir.contains("miniforge") { return ("conda base", nil) }
        if dir.hasPrefix("/opt/homebrew/") || dir.hasPrefix("/usr/local/") { return ("Homebrew Python", nil) }
        if dir.contains("Python.framework") { return ("python.org Python", nil) }
        return ("site-packages", nil)
    }

    // MARK: npm

    static let npmPatterns = [
        "/opt/homebrew/lib/node_modules", "/usr/local/lib/node_modules", "~/.npm-global/lib/node_modules",
        "~/.nvm/versions/node/*/lib/node_modules", "~/.volta/tools/image/packages/*/lib/node_modules",
        "~/.bun/install/global/node_modules", "~/Library/pnpm/global/*/node_modules",
        "~/.local/share/fnm/node-versions/*/installation/lib/node_modules",
    ]

    static func npm(nested: Bool) -> [Package] {
        var pkgs: [Package] = []
        for root in npmPatterns.flatMap(FS.glob).map(FS.resolve).uniqued() {
            for (dir, _) in packageDirs(in: root) {
                guard let p = readPackageJSON(dir, root: root, parent: nil) else { continue }
                pkgs.append(p)
                if nested { walkNested(dir + "/node_modules", parent: p.name, root: root, depth: 0, into: &pkgs) }
            }
        }
        return pkgs
    }

    static func walkNested(_ nm: String, parent: String, root: String, depth: Int, into pkgs: inout [Package]) {
        guard depth < 8, pkgs.count < 25_000, FS.isDir(nm) else { return }
        for (dir, _) in packageDirs(in: nm) {
            if let p = readPackageJSON(dir, root: root, parent: parent) { pkgs.append(p) }
            walkNested(dir + "/node_modules", parent: parent, root: root, depth: depth + 1, into: &pkgs)
        }
    }

    /// node_modules entries, expanding @scope folders.
    static func packageDirs(in nm: String) -> [(String, String)] {
        var out: [(String, String)] = []
        for e in FS.list(nm) where !e.hasPrefix(".") {
            if e.hasPrefix("@") { for s in FS.list(nm + "/" + e) where !s.hasPrefix(".") { out.append(("\(nm)/\(e)/\(s)", "\(e)/\(s)")) } }
            else { out.append(("\(nm)/\(e)", e)) }
        }
        return out
    }

    static func readPackageJSON(_ dir: String, root: String, parent: String?) -> Package? {
        guard let j = jsonObject(FS.read(dir + "/package.json")) as? [String: Any],
              let name = j["name"] as? String, let ver = j["version"] as? String else { return nil }
        var p = Package(ecosystem: .npm, name: name, version: ver, location: dir, source: "global node_modules (\(root))")
        p.parent = parent
        return p
    }

    // MARK: cargo

    static func cargo() -> [Package] {
        let path = Paths.expand("~/.cargo/.crates2.json")
        guard let j = jsonObject(FS.read(path)) as? [String: Any], let installs = j["installs"] as? [String: Any] else { return [] }
        return installs.keys.sorted().compactMap { key in
            // "ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)"
            guard let m = key.firstMatch(#"^(\S+) (\S+) \((registry|sparse)\+[^)]*crates\.io"#) else { return nil }
            return Package(ecosystem: .crates, name: m[1], version: m[2], location: Paths.expand("~/.cargo/bin"), source: "cargo install")
        }
    }

    // MARK: Ruby

    static let gemPatterns = [
        "~/.gem/ruby/*/specifications", "~/.local/share/gem/ruby/*/specifications",
        "/opt/homebrew/lib/ruby/gems/*/specifications", "/usr/local/lib/ruby/gems/*/specifications",
        "/opt/homebrew/Cellar/ruby/*/lib/ruby/gems/*/specifications",
        "~/.rbenv/versions/*/lib/ruby/gems/*/specifications", "~/.rvm/gems/*/specifications",
        "~/.local/share/mise/installs/ruby/*/lib/ruby/gems/*/specifications",
    ]

    static func gems() -> [Package] {
        var pkgs: [Package] = [], seen = Set<String>()
        for dir in gemPatterns.flatMap(FS.glob).map(FS.resolve).uniqued() {
            for sub in [dir, dir + "/default"] {
                for e in FS.list(sub) where e.hasSuffix(".gemspec") {
                    let base = String(e.dropLast(8))
                    // name-1.2.3 or name-1.2.3-arm64-darwin
                    guard let m = base.firstMatch(#"^(.+?)-(\d[^-]*)(?:-.+)?$"#) else { continue }
                    guard seen.insert("\(dir)|\(m[1])|\(m[2])").inserted else { continue }
                    pkgs.append(Package(ecosystem: .rubygems, name: m[1], version: m[2], location: dir, source: sub.hasSuffix("/default") ? "default gem" : "gem"))
                }
            }
        }
        return pkgs
    }

    // MARK: Go

    static func goBinaries(roots: [String]) -> [Package] {
        var pkgs: [Package] = []
        for root in roots.map(Paths.expand).uniqued() where FS.isDir(root) {
            for e in FS.list(root) where !e.hasPrefix(".") {
                let p = FS.resolve(root + "/" + e)
                guard let info = GoBuildInfo.read(path: p) else { continue }
                pkgs += info.packages(binary: e, path: p)
            }
        }
        // The same binary can be linked from several bins.
        var seen = Set<String>()
        return pkgs.filter { seen.insert($0.id).inserted }
    }
}

/// Go embeds its toolchain version and module list in every binary (`go version -m`).
/// Parsed directly so the Go toolchain doesn't need to be installed.
public struct GoBuildInfo: Equatable {
    public var goVersion: String
    public var mainPath: String
    public var mainVersion: String
    public var deps: [(path: String, version: String)]

    public static func == (a: GoBuildInfo, b: GoBuildInfo) -> Bool {
        a.goVersion == b.goVersion && a.mainPath == b.mainPath && a.deps.map(\.path) == b.deps.map(\.path)
    }

    static let magic = Data([0xff] + Array(" Go buildinf:".utf8))

    public static func read(path: String) -> GoBuildInfo? {
        guard let size = (try? FileManager.default.attributesOfItem(atPath: path))?[.size] as? Int, size > 1024, size < 600_000_000,
              let h = FileHandle(forReadingAtPath: path) else { return nil }
        let head = h.readData(ofLength: 4)
        try? h.close()
        // Mach-O 64 (feedfacf / cffaedfe) or universal (cafebabe); ELF for tests.
        let sig = [UInt8](head)
        let ok = sig == [0xcf, 0xfa, 0xed, 0xfe] || sig == [0xfe, 0xed, 0xfa, 0xcf] || sig == [0xca, 0xfe, 0xba, 0xbe] || sig == [0x7f, 0x45, 0x4c, 0x46]
        guard ok, let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe) else { return nil }
        return parse(data)
    }

    public static func parse(_ data: Data) -> GoBuildInfo? {
        guard let r = data.range(of: magic) else { return nil }
        let base = r.lowerBound
        guard data.count > base + 32 else { return nil }
        let flags = data[base + 15]
        guard flags & 0x2 != 0 else { return nil }   // pre-1.18 pointer format: not supported
        var i = base + 32
        func varString() -> String? {
            var len = 0, shift = 0
            while i < data.count {
                let b = Int(data[i]); i += 1
                len |= (b & 0x7f) << shift
                if b & 0x80 == 0 { break }
                shift += 7
                if shift > 35 { return nil }
            }
            guard len >= 0, i + len <= data.count else { return nil }
            let s = String(decoding: data[i..<(i + len)], as: UTF8.self)
            i += len
            return s
        }
        guard let ver = varString(), let mod = varString() else { return nil }
        var info = GoBuildInfo(goVersion: ver, mainPath: "", mainVersion: "", deps: [])
        for line in mod.split(separator: "\n") {
            let f = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            guard f.count >= 2 else { continue }
            let key = f[0].filter { $0.isLetter || $0 == "=" || $0 == ">" }   // strip the 16-byte sentinel
            switch key {
            case "path": info.mainPath = f[1]
            case "mod": info.mainPath = f[1]; info.mainVersion = f.count > 2 ? f[2] : ""
            case "dep": info.deps.append((f[1], f.count > 2 ? f[2] : ""))
            case "=>": if !info.deps.isEmpty, f.count > 2 { info.deps[info.deps.count - 1] = (f[1], f[2]) }
            default: break
            }
        }
        return info
    }

    func packages(binary: String, path: String) -> [Package] {
        var out: [Package] = []
        let gv = goVersion.split(separator: " ").first.map(String.init) ?? goVersion
        if gv.hasPrefix("go") {
            var p = Package(ecosystem: .go, name: "stdlib", version: String(gv.dropFirst(2)), location: path, source: "Go toolchain \(gv)")
            p.parent = binary
            out.append(p)
        }
        if !mainPath.isEmpty, !mainVersion.isEmpty, mainVersion != "(devel)" {
            var p = Package(ecosystem: .go, name: mainPath, version: mainVersion.hasPrefix("v") ? String(mainVersion.dropFirst()) : mainVersion, location: path, source: "Go main module")
            p.parent = binary
            out.append(p)
        }
        for d in deps where !d.version.isEmpty && d.version != "(devel)" {
            var p = Package(ecosystem: .go, name: d.path, version: d.version.hasPrefix("v") ? String(d.version.dropFirst()) : d.version, location: path, source: "Go module dependency")
            p.parent = binary
            out.append(p)
        }
        return out
    }
}
