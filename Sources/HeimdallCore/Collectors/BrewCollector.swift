import Foundation

public struct CollectorOutput: Sendable {
    public var packages: [Package] = []
    public var status: [SourceStatus] = []
    /// Raw `brew vulns --json` output, when the installed Homebrew has the command.
    public var brewVulns: Data? = nil
}

/// Homebrew formulae and casks, read with `brew info --json=v2 --installed` as the user.
public enum BrewCollector {
    public static func collect(useBrewVulns: Bool) async -> CollectorOutput {
        var out = CollectorOutput()
        guard let brew = Shell.which("brew") else {
            out.status.append(SourceStatus(name: "Homebrew", state: .skipped, detail: "brew is not installed or not on PATH"))
            return out
        }
        let r = await Shell.run(brew, ["info", "--json=v2", "--installed"], timeout: 180)
        guard r.ok, let j = jsonObject(Data(r.stdout.utf8)) as? [String: Any] else {
            out.status.append(SourceStatus(name: "Homebrew", state: .failed, detail: "brew info failed: \(r.stderr.trimmed.prefix(200))"))
            return out
        }
        let prefix = (await Shell.run(brew, ["--prefix"], timeout: 20)).stdout.trimmed
        out.packages = parse(j, prefix: prefix)
        let nf = out.packages.filter { $0.ecosystem == .homebrew }.count, nc = out.packages.count - nf
        out.status.append(SourceStatus(name: "Homebrew", state: .ok, detail: "\(nf) formulae, \(nc) casks via brew info (\(brew))", count: out.packages.count, updated: Date()))

        if useBrewVulns {
            let help = await Shell.run(brew, ["vulns", "--help"], timeout: 30)
            if help.ok {
                // Exits non-zero when it finds something, so judge by the output, not the status.
                let v = await Shell.run(brew, ["vulns", "--json"], timeout: 600)
                let t = v.stdout.trimmed
                if t.hasPrefix("{") || t.hasPrefix("[") {
                    out.brewVulns = Data(t.utf8)
                    out.status.append(SourceStatus(name: "brew vulns", state: .ok, detail: "Homebrew's own advisory check", updated: Date()))
                } else {
                    out.status.append(SourceStatus(name: "brew vulns", state: .warning, detail: "no JSON output; using OSV instead"))
                }
            } else {
                out.status.append(SourceStatus(name: "brew vulns", state: .skipped, detail: "not available in this Homebrew; using OSV (GIT) lookups"))
            }
        }
        return out
    }

    static func parse(_ j: [String: Any], prefix: String) -> [Package] {
        var pkgs: [Package] = []
        for f in j["formulae"] as? [[String: Any]] ?? [] {
            guard let name = f["name"] as? String else { continue }
            let installed = (f["installed"] as? [[String: Any]] ?? []).compactMap { $0["version"] as? String }
            let linked = f["linked_keg"] as? String
            // The linked keg is the one in use; otherwise the newest keg (old kegs linger until `brew cleanup`).
            let ver = (linked.flatMap { installed.contains($0) ? $0 : nil }) ?? installed.sorted { Version.less($1, $0) }.first
            guard let ver else { continue }
            var p = Package(ecosystem: .homebrew, name: name, version: Version.stripBrewRevision(ver),
                            location: prefix.isEmpty ? "" : "\(prefix)/Cellar/\(name)/\(ver)", source: "brew info")
            let urls = f["urls"] as? [String: Any]
            let candidates = [((urls?["stable"] as? [String: Any])?["url"] as? String), ((urls?["head"] as? [String: Any])?["url"] as? String), f["homepage"] as? String]
            p.repo = candidates.compactMap { $0 }.compactMap(repoURL).first
            p.outdated = f["outdated"] as? Bool ?? false
            p.modified = FS.mtime(p.location)
            pkgs.append(p)
        }
        for c in j["casks"] as? [[String: Any]] ?? [] {
            guard let token = c["token"] as? String, let ver = c["installed"] as? String else { continue }
            var p = Package(ecosystem: .cask, name: token, version: ver, location: prefix.isEmpty ? "" : "\(prefix)/Caskroom/\(token)", source: "brew info")
            p.outdated = c["outdated"] as? Bool ?? false
            // Remember which .app bundles this cask put in /Applications so app findings can say `brew upgrade --cask`.
            p.parent = nil
            p.bundleID = appNames(c).joined(separator: "|")
            pkgs.append(p)
        }
        return pkgs
    }

    static func appNames(_ cask: [String: Any]) -> [String] {
        var names: [String] = []
        for a in cask["artifacts"] as? [Any] ?? [] {
            guard let d = a as? [String: Any], let apps = d["app"] as? [Any] else { continue }
            for x in apps {
                if let s = x as? String { names.append((s as NSString).lastPathComponent) }
                else if let o = x as? [String: Any], let t = o["target"] as? String { names.append((t as NSString).lastPathComponent) }
            }
        }
        return names
    }

    /// github / gitlab / codeberg repository root from a download or homepage URL.
    static func repoURL(_ u: String) -> String? {
        guard let m = u.firstMatch(#"^https?://(github\.com|gitlab\.com|codeberg\.org)/([^/]+)/([^/#?]+?)(?:\.git)?(?:[/#?]|$)"#, options: .caseInsensitive) else { return nil }
        return "https://\(m[1].lowercased())/\(m[2])/\(m[3])"
    }
}
