import Foundation

/// Whether a vulnerable thing is reachable on this Mac. Two packages can carry the same advisory
/// and not be the same problem: one is listening on a socket right now, the other is a copy of a
/// library inside a program that hasn't run since it was installed. Everything here is read from
/// the account's own view of the machine — `ps`, `lsof`, launchd's user domain, and the
/// LaunchAgent plists a normal user can read. Nothing is launched and no process is inspected.
public enum ExposureCollector {
    public static func annotate(_ packages: inout [Package]) async -> SourceStatus {
        let processes = await runningProcesses()
        let ports = await listeningPorts()
        let agents = agentPrograms()
        let loaded = await loadedLabels()

        guard !processes.isEmpty else {
            return SourceStatus(name: "Reachability", state: .warning,
                                detail: "ps returned nothing, so nothing is ranked on whether it runs")
        }
        let paths = processes.map(\.path)
        for i in packages.indices {
            packages[i].exposure = exposure(packages[i], paths: paths, processes: processes,
                                            ports: ports, agents: agents, loaded: loaded)
        }
        // A framework inside an app is reached through the app, not on its own: the running
        // process is the host's, and the host's answer is the honest one for both.
        let hosts = Dictionary(packages.filter { $0.ecosystem == .app && $0.parent == nil }.map { ($0.name, $0) },
                               uniquingKeysWith: { a, _ in a })
        for i in packages.indices {
            guard packages[i].exposure == nil || packages[i].exposure?.any == false,
                  let parent = packages[i].parent, let host = hosts[parent], let e = host.exposure, e.any else { continue }
            var inherited = e
            inherited.notes = ["reached through \(parent)"] + e.notes
            packages[i].exposure = inherited
        }

        let answered = packages.filter { $0.exposure != nil }
        let reachable = answered.filter { $0.exposure?.any == true }.count
        let listening = answered.filter { $0.exposure?.listening == true }.count
        var detail = "\(reachable) of \(answered.count) answerable packages are running, listening or started by launchd"
        if listening > 0 { detail += "; \(listening) listening on a socket" }
        if ports.isEmpty { detail += ". lsof reported no listening sockets for this account" }
        return SourceStatus(name: "Reachability", state: .ok, detail: detail, count: reachable, updated: Date())
    }

    // MARK: What the system is doing

    struct Proc: Sendable { let pid: Int; let path: String }

    /// `ps -axo pid=,comm=` gives one executable path per process. Paths contain spaces, so the
    /// pid is read off the front and the rest is the path.
    static func runningProcesses() async -> [Proc] {
        guard let ps = Shell.systemTool("ps") else { return [] }
        let r = await Shell.run(ps, ["-axo", "pid=,comm="], timeout: 20)
        return r.ok ? parseProcesses(r.stdout) : []
    }

    static func parseProcesses(_ text: String) -> [Proc] {
        var out: [Proc] = []
        for line in text.split(whereSeparator: \.isNewline) {
            let t = String(line).trimmed
            guard let space = t.firstIndex(of: " "), let pid = Int(t[t.startIndex..<space]) else { continue }
            let path = String(t[space...]).trimmed
            if path.hasPrefix("/") { out.append(Proc(pid: pid, path: path)) }
        }
        return out
    }

    /// Listening TCP sockets, by pid. Without root `lsof` only reports this account's processes,
    /// which is the same boundary the rest of Heimdall works within.
    static func listeningPorts() async -> [Int: [Int]] {
        guard let lsof = Shell.systemTool("lsof") else { return [:] }
        let r = await Shell.run(lsof, ["-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pn"], timeout: 25)
        return parsePorts(r.stdout)
    }

    /// `lsof -F pn` emits one field per line: `p` starts a process, `n` is an address it holds.
    static func parsePorts(_ text: String) -> [Int: [Int]] {
        var out: [Int: [Int]] = [:]
        var pid: Int?
        for line in text.split(whereSeparator: \.isNewline) {
            let s = String(line)
            guard let kind = s.first else { continue }
            let value = String(s.dropFirst())
            switch kind {
            case "p": pid = Int(value)
            case "n":
                guard let pid, let colon = value.lastIndex(of: ":"), let port = Int(value[value.index(after: colon)...]) else { continue }
                out[pid, default: []].append(port)
            default: break
            }
        }
        return out.mapValues { $0.uniqued().sorted() }
    }

    /// LaunchAgent and LaunchDaemon plists readable as this user, as (program path, label) pairs.
    /// A job here is started by launchd rather than by you, which is what makes it interesting.
    static func agentPrograms() -> [(program: String, label: String)] {
        var out: [(String, String)] = []
        for dir in ["~/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons"].map(Paths.expand) {
            for f in FS.list(dir) where f.hasSuffix(".plist") {
                guard let d = FS.read(dir + "/" + f),
                      let pl = (try? PropertyListSerialization.propertyList(from: d, format: nil)) as? [String: Any] else { continue }
                let label = (pl["Label"] as? String) ?? (f as NSString).deletingPathExtension
                var program = pl["Program"] as? String
                if program == nil, let args = pl["ProgramArguments"] as? [Any] { program = args.first as? String }
                guard let program, program.hasPrefix("/") else { continue }
                out.append((program, label))
            }
        }
        return out
    }

    /// Labels launchd has loaded in this user's domain. A loaded job is one launchd starts without
    /// you asking, which is the part that matters even when it isn't running this second.
    static func loadedLabels() async -> Set<String> {
        guard let launchctl = Shell.systemTool("launchctl") else { return [] }
        let r = await Shell.run(launchctl, ["list"], timeout: 20)
        return parseLabels(r.stdout)
    }

    static func parseLabels(_ text: String) -> Set<String> {
        var out: Set<String> = []
        for line in text.split(whereSeparator: \.isNewline).dropFirst() {
            let cols = line.split(separator: "\t")
            if let label = cols.last, !label.isEmpty { out.insert(String(label).trimmed) }
        }
        return out
    }

    // MARK: Matching it to packages

    /// Only something with a place on disk can be matched to a process. A Python package runs
    /// inside an interpreter and a browser extension inside a browser, so the first is left
    /// unanswered — nil, not "idle" — and the second follows its browser.
    static func exposure(_ p: Package, paths: [String], processes: [Proc], ports: [Int: [Int]],
                         agents: [(program: String, label: String)], loaded: Set<String>) -> Exposure? {
        switch p.ecosystem {
        case .browserExtension: return browserExposure(p, paths: paths)
        case .macos, .pypi, .npm, .crates, .rubygems: return nil
        case .app, .cask, .homebrew, .go: break
        }
        var e = Exposure()
        for proc in processes where owns(p, proc.path) {
            e.running = true
            if e.notes.count < 3 { e.notes.append("running: \(proc.path)") }
            if let found = ports[proc.pid] { e.ports += found }
        }
        for a in agents where owns(p, a.program) {
            e.autostart = true
            if e.notes.count < 4 { e.notes.append("started by launchd: \(a.label)") }
        }
        if !e.autostart, let id = p.bundleID, !id.isEmpty, id.contains("."),
           loaded.contains(where: { $0 == id || $0.hasPrefix(id + ".") }) {
            e.autostart = true
            e.notes.append("loaded in launchd's user domain as \(id)")
        }
        e.ports = e.ports.uniqued().sorted()
        return e
    }

    /// An extension is only reachable while its browser is open.
    static func browserExposure(_ p: Package, paths: [String]) -> Exposure? {
        guard let browser = p.browser, !browser.isEmpty else { return nil }
        var e = Exposure()
        let needle = browser.lowercased()
        for path in paths {
            guard let appRange = path.range(of: ".app/") else { continue }
            let bundle = String(path[path.startIndex..<appRange.lowerBound]).lowercased()
            if (bundle as NSString).lastPathComponent.contains(needle) {
                e.running = true
                e.notes = ["\(browser) is running"]
                break
            }
        }
        return e
    }

    static func owns(_ p: Package, _ path: String) -> Bool {
        if !p.location.isEmpty, path == p.location || path.hasPrefix(p.location + "/") { return true }
        if p.ecosystem == .homebrew {
            // Homebrew links its programs into <prefix>/bin, and that is the path a process is
            // started from, so the keg path on its own would miss most of them.
            if path.contains("/Cellar/\(p.name)/") { return true }
            if (path as NSString).lastPathComponent == p.name, path.contains("/bin/") { return true }
        }
        return false
    }
}
