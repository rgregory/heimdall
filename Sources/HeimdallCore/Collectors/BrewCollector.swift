import Foundation

public struct CollectorOutput: Sendable {
    public var packages: [Package] = []
    public var status: [SourceStatus] = []
    /// Raw `brew vulns --json` output, when the installed Homebrew has the command.
    public var brewVulns: Data? = nil
}

/// Homebrew formulae and casks, read with `brew info --json=v2 --installed` as the user.
public enum BrewCollector {
    public static func collect(useBrewVulns: Bool, offline: Bool = false) async -> CollectorOutput {
        await collect(useBrewVulns: useBrewVulns, offline: offline, brew: Shell.which("brew")) { exe, args, timeout in
            await Shell.run(exe, args, timeout: timeout)
        }
    }

    static func collect(useBrewVulns: Bool, offline: Bool, brew: String?,
                        run: (String, [String], TimeInterval) async -> ShellResult) async -> CollectorOutput {
        var out = CollectorOutput()
        guard let brew else {
            out.status.append(SourceStatus(name: "Homebrew", state: .skipped, detail: "brew is not installed or not on PATH"))
            return out
        }
        let r = await run(brew, ["info", "--json=v2", "--installed"], 180)
        guard r.ok, let j = jsonObject(Data(r.stdout.utf8)) as? [String: Any] else {
            out.status.append(SourceStatus(name: "Homebrew", state: .failed, detail: "brew info failed: \(r.stderr.trimmed.prefix(200))"))
            return out
        }
        let prefix = (await run(brew, ["--prefix"], 20)).stdout.trimmed
        out.packages = parse(j, prefix: prefix)
        let nf = out.packages.filter { $0.ecosystem == .homebrew }.count, nc = out.packages.count - nf
        out.status.append(SourceStatus(name: "Homebrew", state: .ok, detail: "\(nf) formulae, \(nc) casks via brew info (\(brew))", count: out.packages.count, updated: Date()))

        if useBrewVulns && !offline {
            let help = await run(brew, ["vulns", "--help"], 30)
            if help.ok {
                // Exits non-zero when it finds something, so judge by the output, not the status.
                let v = await run(brew, ["vulns", "--json"], 600)
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
        if useBrewVulns && offline {
            out.status.append(SourceStatus(name: "brew vulns", state: .skipped, detail: "offline; using cached OSV answers only"))
        }
        return out
    }

    /// Homebrew writes an INSTALL_RECEIPT.json into every keg with the epoch second it was
    /// poured. It is the only record of when this Mac got this version, and it goes away with
    /// the keg at the next `brew cleanup`, so read it on every scan rather than on demand.
    static func installDate(_ keg: String) -> Date? {
        guard !keg.isEmpty,
              let d = try? Data(contentsOf: URL(fileURLWithPath: keg + "/INSTALL_RECEIPT.json")),
              let j = jsonObject(d) as? [String: Any] else { return nil }
        guard let t = j["time"] as? Double ?? (j["time"] as? Int).map(Double.init) else { return nil }
        return Date(timeIntervalSince1970: t)
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
            p.maintenance = maintenance(f)
            p.modified = FS.mtime(p.location)
            p.installed = installDate(p.location)
            pkgs.append(p)
        }
        for c in j["casks"] as? [[String: Any]] ?? [] {
            guard let token = c["token"] as? String, let ver = c["installed"] as? String else { continue }
            var p = Package(ecosystem: .cask, name: token, version: ver, location: prefix.isEmpty ? "" : "\(prefix)/Caskroom/\(token)", source: "brew info")
            p.outdated = c["outdated"] as? Bool ?? false
            p.maintenance = maintenance(c)
            // Remember which .app bundles this cask put in /Applications so app findings can say `brew upgrade --cask`.
            p.parent = nil
            p.bundleID = appNames(c).joined(separator: "|")
            pkgs.append(p)
        }
        return pkgs
    }

    /// Homebrew says so itself: a disabled formula can't be installed any more, and a deprecated
    /// one is on its way out. Either way no newer version is coming through brew, which is the
    /// part that matters once an advisory names it.
    static func maintenance(_ j: [String: Any]) -> Maintenance? {
        let disabled = j["disabled"] as? Bool ?? false
        let deprecated = j["deprecated"] as? Bool ?? false
        guard disabled || deprecated else { return nil }
        let prefix = disabled ? "disable" : "deprecation"
        let raw = (j["\(prefix)_reason"] as? String)?.trimmed ?? ""
        let date = (j["\(prefix)_date"] as? String).flatMap { MaintenanceCheck.day.date(from: String($0.prefix(10))) }
        let replacement = (j["\(prefix)_replacement"] as? String)?.trimmed
        let what = disabled ? "Homebrew has disabled this formula" : "Homebrew has deprecated this formula"
        let why = reason(raw)
        return Maintenance(state: disabled ? .disabled : .deprecated,
                           reason: why.isEmpty ? "\(what)." : "\(what): \(why).",
                           source: "brew info", since: date,
                           replacement: (replacement?.isEmpty ?? true) ? nil : replacement)
    }

    /// Homebrew's reasons are tokens. These are the ones that say something a person would want
    /// to read; anything else is passed through as it came.
    static func reason(_ raw: String) -> String {
        switch raw {
        case "": return ""
        case "unmaintained": return "nobody is maintaining it upstream"
        case "deprecated_upstream": return "its own authors deprecated it"
        case "repo_archived": return "the upstream repository is archived"
        case "repo_removed": return "the upstream repository is gone"
        case "does_not_build": return "it no longer builds"
        case "no_license": return "it has no license"
        case "versioned_formula": return "Homebrew only keeps current versions"
        case "unsupported": return "it is unsupported"
        case "discontinued": return "it is discontinued"
        case "moved_to_mas": return "it moved to the Mac App Store"
        default: return raw.replacingOccurrences(of: "_", with: " ")
        }
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
