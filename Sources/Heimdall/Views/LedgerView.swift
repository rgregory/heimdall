import HeimdallCore
import SwiftUI

/// Modern-layout tables: all advisories, inventory, sources.
struct LedgerRow: Identifiable {
    var finding: Finding
    var vuln: Vulnerability
    var id: String { finding.id + "|" + vuln.id }
    var package: String { finding.package.displayName }
    var version: String { finding.package.version }
    var ecosystem: String { finding.package.ecosystem.title }
    var advisory: String { vuln.headlineID }
    var severityRank: Int { vuln.severity.rank }
    var cvss: Double { vuln.cvss ?? -1 }
    var epss: Double { vuln.epss ?? -1 }
    var kev: Int { vuln.isKEV ? 1 : 0 }
    var fixed: String { firstFix(vuln, above: finding.package.version) }
    var summary: String { vuln.summary }
    /// The one thing you would update to be rid of this row: the binary or app carrying the
    /// vulnerable code, or the package itself when nothing carries it.
    var carrier: String { finding.package.parent ?? finding.package.ownerProduct ?? finding.package.name }
    /// Days this advisory has been open here; -1 when there is no history for it yet.
    var age: Int { finding.ageDays ?? -1 }
    /// Running, started by launchd, or listening right now.
    var reachable: Bool { finding.package.exposure?.any == true }
    /// Something to install tonight, as opposed to a wait on whoever ships the fix.
    var fixable: Bool { finding.awaitingRelease != true && !finding.fixHint.isEmpty }
    /// Sort key for the signals column: exploited, then public exploit code, then reachable.
    var signalRank: Int { (vuln.isKEV ? 4 : 0) + (vuln.hasPublicExploit ? 2 : 0) + (reachable ? 1 : 0) }
    var exposure: String {
        guard let e = finding.package.exposure, e.any else { return "" }
        if e.listening { return "listening " + e.ports.map(String.init).joined(separator: ", ") }
        return e.running ? "running" : "launchd"
    }
}

struct ModernLedger: View {
    @Environment(AppModel.self) private var model
    @State private var sort = [KeyPathComparator(\LedgerRow.kev, order: .reverse), KeyPathComparator(\LedgerRow.severityRank, order: .reverse), KeyPathComparator(\LedgerRow.cvss, order: .reverse)]
    @State private var selection: LedgerRow.ID?
    @State private var filter = LedgerFilter()
    @AppStorage("ledgerView") private var view = LedgerView.bars

    var body: some View {
        let all = model.findings(for: .ledger).flatMap { f in f.vulns.map { LedgerRow(finding: f, vuln: $0) } }.sorted(using: sort)
        let rows = all.filter(filter.matches)
        VStack(alignment: .leading, spacing: 0) {
            // The three pictures scroll inside themselves, so they stack under the band
            // happily. The table does not: it needs the pane, with the band as an inset.
            switch view {
            case .table:
                table(rows, everything: all)
                    .safeAreaInset(edge: .top, spacing: 0) {
                        AdvisoryInsights(rows: all, filter: $filter, view: $view)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(.bar)
                    }
            default:
                VStack(alignment: .leading, spacing: 0) {
                    AdvisoryInsights(rows: all, filter: $filter, view: $view)
                    switch view {
                    case .bars: AdvisoryBars(rows: rows, open: pick)
                    case .dots: AdvisoryDots(rows: rows, open: pick)
                    default: AdvisoryMap(rows: rows, open: pick)
                    }
                }
            }
        }
    }

    /// Clicking a package in any of the pictures means "show me these rows".
    func pick(_ carrier: String) {
        filter.carrier = carrier
        view = .table
    }

    /// The same conditions, spelled with "or", for the button that switches to them.
    var orSummary: String {
        var f = filter
        f.matchAll = false
        return f.summary
    }

    func table(_ rows: [LedgerRow], everything: [LedgerRow]) -> some View {
        Table(rows, selection: $selection, sortOrder: $sort) {
            TableColumn("", value: \.signalRank) { r in SignalCell(row: r) }
                .width(54)
            TableColumn("Package", value: \.package).width(min: 120, ideal: 180)
            TableColumn("Version", value: \.version) { r in Text(r.version).font(.system(.body, design: .monospaced)).foregroundStyle(.secondary) }
                .width(min: 60, ideal: 90)
            TableColumn("Kind", value: \.ecosystem).width(min: 70, ideal: 100)
            TableColumn("Advisory", value: \.advisory).width(min: 110, ideal: 140)
            TableColumn("Severity", value: \.severityRank) { r in SeverityCell(severity: r.vuln.severity, cvss: r.cvss) }
                .width(min: 96, ideal: 118)
            TableColumn("EPSS", value: \.epss) { r in
                // Exploit probability is almost always small; a bar against 20% makes the
                // difference between 0.1% and 8% visible, which the number alone does not.
                if r.epss >= 0 { ScoreCell(value: r.epss * 100, ceiling: 20, text: String(format: "%.1f%%", r.epss * 100), tint: .purple) }
                else { Text("—").foregroundStyle(.tertiary) }
            }
            .width(64)
            TableColumn("Age", value: \.age) { r in
                Text(r.age < 0 ? "—" : r.age == 0 ? "today" : "\(r.age)d")
                    .font(.system(size: 11.5).monospacedDigit())
                    .foregroundStyle(r.age >= 30 ? Color.orange : Color.secondary)
                    .help(r.age < 0 ? "No history for this one yet" : "Open here for \(plural(r.age, "day"))")
            }
            .width(50)
            TableColumn("Fixed in", value: \.fixed) { r in Text(r.fixed).font(.system(.body, design: .monospaced)) }.width(min: 60, ideal: 90)
            TableColumn("Summary", value: \.summary)
        }
        .contextMenu(forSelectionType: LedgerRow.ID.self) { ids in
            if let id = ids.first, let r = rows.first(where: { $0.id == id }) {
                Button("Show Details") { model.selectedVuln = VulnSelection(finding: r.finding, vuln: r.vuln) }
                Button("Copy Fix Command") { model.copy(commandPart(r.finding.fixHint)) }
                Button("Ignore \(r.advisory) for \(r.finding.package.name)") { model.toggleMute(r.finding, r.vuln) }
            }
        } primaryAction: { ids in
            if let id = ids.first, let r = rows.first(where: { $0.id == id }) { model.selectedVuln = VulnSelection(finding: r.finding, vuln: r.vuln) }
        }
        .overlay {
            if rows.isEmpty, !everything.isEmpty {
                VStack(spacing: 10) {
                    Text("Nothing is \(filter.summary) at once.").font(.system(size: 13.5))
                    if filter.matchAll, filter.conditions > 1 {
                        // Stacked conditions coming up empty is usually good news, not a dead
                        // end: the same switches read as "any" answer a question worth asking.
                        Text("That is the healthy answer to an “and”. Ask the other question instead:")
                            .font(.system(size: 12)).foregroundStyle(.secondary)
                        Button("Show anything that is \(orSummary)") {
                            withAnimation(.snappy(duration: 0.2)) { filter.matchAll = false }
                        }
                        .controlSize(.small)
                    }
                }
                .multilineTextAlignment(.center).padding(.horizontal, 40)
            }
        }
    }
}

extension Package {
    var latestLabel: String { outdated ? (latest ?? "newer") : (latest == nil ? "" : "current") }
}

/// One line in the Inventory: a package, the identical copies of it found elsewhere, and the
/// cask that installed it when an app came from Homebrew. The scanner is right to track every
/// copy — each one is matched against advisories separately — but a reader looking for what is
/// on the Mac does not want certifi three times because three virtualenvs have it.
struct InventoryRow: Identifiable {
    var package: Package
    var copies: [Package]
    var viaCask: String?
    var vulnerable: Bool

    var id: String { package.id }
    var count: Int { copies.count }
    var name: String { package.displayName }
    var version: String { package.version }
    var kind: String { package.ecosystem.title }
    var latestLabel: String { package.latestLabel }
    var coverage: PackageCoverage.State { package.coverage?.state ?? .pending }
    var source: String { package.source }
    var location: String { package.location }
    /// Every place this was found, for the row's tooltip.
    var allLocations: String {
        copies.map(\.location).filter { !$0.isEmpty }.joined(separator: "\n")
    }

    /// How much a copy has to say: a checked one speaks for its twins, an unchecked one does not.
    static func rank(_ p: Package) -> Int {
        switch p.coverage?.state {
        case .checked: return 3
        case .cached: return 2
        case .pending: return 1
        default: return 0
        }
    }

    static func build(_ packages: [Package], vulnerable: Set<String>, collapse: Bool) -> [InventoryRow] {
        guard collapse else {
            return packages.map { InventoryRow(package: $0, copies: [$0], viaCask: nil, vulnerable: vulnerable.contains($0.id)) }
        }
        // A cask lists the app bundles it installs (BrewCollector stores them in `bundleID`),
        // so the cask row and the .app row it produced can be matched exactly rather than by
        // comparing names and hoping.
        var caskByApp: [String: Package] = [:]
        for c in packages where c.ecosystem == .cask {
            for n in (c.bundleID ?? "").split(separator: "|") {
                caskByApp[String(n).lowercased()] = c
            }
        }
        var absorbed = Set<String>(), order: [String] = []
        var groups: [String: [Package]] = [:], viaCask: [String: String] = [:]
        for p in packages where p.ecosystem != .cask {
            let key = "\(p.ecosystem.rawValue)|\(p.name.lowercased())|\(p.version)|\(p.parent ?? "")"
            if groups[key] == nil { order.append(key) }
            groups[key, default: []].append(p)
            if p.ecosystem == .app {
                let bundle = (p.location as NSString).lastPathComponent.lowercased()
                if let c = caskByApp[bundle] {
                    absorbed.insert(c.id)
                    viaCask[key] = c.name
                }
            }
        }
        // Casks that did not install an app bundle we can see stay as rows of their own.
        for c in packages where c.ecosystem == .cask && !absorbed.contains(c.id) {
            let key = "cask|\(c.name.lowercased())|\(c.version)|"
            if groups[key] == nil { order.append(key) }
            groups[key, default: []].append(c)
        }
        return order.map { k in
            let list = groups[k]!
            let rep = list.max { rank($0) < rank($1) } ?? list[0]
            return InventoryRow(package: rep, copies: list, viaCask: viaCask[k],
                                vulnerable: list.contains { vulnerable.contains($0.id) })
        }
    }
}

struct ModernInventory: View {
    @Environment(AppModel.self) private var model
    @State private var sort = [KeyPathComparator(\InventoryRow.name)]
    @State private var filter = InventoryFilter()
    @AppStorage("inventoryCharts") private var bandExpanded = false
    @AppStorage("inventoryCollapse") private var collapse = true

    var body: some View {
        let vulnerable = Set(model.visible?.findings.map(\.package.id) ?? [])
        let exploited = Set(model.visible?.kevFindings.map(\.package.id) ?? [])
        let q = model.search.lowercased()
        let everything = model.visible?.packages ?? []
        let kept = everything
            .filter { filter.matches($0, vulnerable: vulnerable) }
            .filter { q.isEmpty || $0.name.lowercased().contains(q) || ($0.parent ?? "").lowercased().contains(q) }
        let rows = InventoryRow.build(kept, vulnerable: vulnerable, collapse: collapse).sorted(using: sort)
        // The table owns the pane and the band rides above it as a safe-area inset — the same
        // shape the sidebar uses for its scan footer. Stacked in a VStack instead, the two
        // negotiate for height with nothing bounding them, and the loser is pushed off the
        // top of the window along with the page title.
        table(rows)
        .safeAreaInset(edge: .top, spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                InventoryOverview(packages: everything, vulnerableIDs: vulnerable, exploitedIDs: exploited,
                                  filter: $filter, expanded: $bandExpanded)
                    .frame(height: InventoryOverview.height(expanded: bandExpanded))
                HStack(spacing: 10) {
                    Text(countLine(rows: rows.count, installs: kept.count, all: everything.count))
                        .font(.system(size: 11.5)).foregroundStyle(.secondary)
                    Toggle("Collapse duplicates", isOn: $collapse)
                        .toggleStyle(.checkbox).controlSize(.small)
                        .help("Show one line per thing installed, with copies counted, and apps merged with the cask that installed them")
                    Spacer()
                }
                .padding(.horizontal, 28).padding(.bottom, 4)
                .frame(height: 20)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.bar)
        }
        .onAppear {
            guard model.focusUnchecked else { return }
            filter = InventoryFilter(unchecked: true)
            model.focusUnchecked = false
        }
    }

    func countLine(rows: Int, installs: Int, all: Int) -> String {
        var s = plural(rows, "package")
        if collapse && installs > rows { s += " · \(installs.formatted()) installs" }
        if installs != all { s += " of \(all.formatted())" }
        return s
    }

    func table(_ rows: [InventoryRow]) -> some View {
        Table(rows, sortOrder: $sort) {
            TableColumn("", value: \.name) { r in
                SeverityRing(severity: r.vulnerable ? .high : .none, exploited: false).scaleEffect(0.7)
            }
            .width(20)
            TableColumn("Name", value: \.name) { r in
                HStack(spacing: 6) {
                    Text(r.name).lineLimit(1).truncationMode(.middle)
                    if r.count > 1 { ThingsTag(text: "\u{00d7}\(r.count)") }
                    if let cask = r.viaCask { ThingsTag(text: "cask: \(cask)", tint: .orange) }
                }
            }
            .width(min: 140, ideal: 240)
            TableColumn("Version", value: \.version) { r in Text(r.version).font(.system(.body, design: .monospaced)) }
                .width(min: 70, ideal: 100)
            TableColumn("Kind", value: \.kind).width(min: 80, ideal: 110)
            TableColumn("Latest", value: \.latestLabel) { r in
                Text(r.latestLabel).font(.system(.body, design: .monospaced))
                    .foregroundStyle(r.package.outdated ? Color.blue : Color.secondary)
            }
            .width(min: 60, ideal: 100)
            TableColumn("Coverage") { r in
                CoverageCell(state: r.coverage)
                    .help(r.package.coverage?.detail ?? "Rescan to record coverage.")
            }
            .width(min: 100, ideal: 150)
            TableColumn("Found via", value: \.source).width(min: 100, ideal: 160)
            TableColumn("Location", value: \.location) { r in
                Text(r.count > 1 ? "\(r.location) + \(r.count - 1) more" : r.location)
                    .lineLimit(1).truncationMode(.middle).help(r.allLocations)
            }
        }
    }
}

/// Coverage as a dot and a word. Eight hundred rows of orange sentences read as an error
/// state; the same fact in the margin reads as what it is — a note about reach.
struct CoverageCell: View {
    var state: PackageCoverage.State

    var tint: Color {
        switch state {
        case .checked: return .green
        case .cached: return .teal
        case .pending: return .blue
        case .noMapping: return .orange
        case .unavailable: return .red
        case .disabled: return .secondary
        }
    }

    var body: some View {
        HStack(spacing: 5) {
            Circle().fill(tint.opacity(state == .checked ? 0.9 : 0.55)).frame(width: 6, height: 6)
            Text(state.title).font(.system(size: 11.5))
                .foregroundStyle(state == .checked ? Color.secondary : Color.primary.opacity(0.75))
                .lineLimit(1)
        }
    }
}

struct ModernSources: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(model.report?.sources ?? []) { s in
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Image(systemName: icon(s.state)).foregroundStyle(tint(s.state))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(s.name).font(.system(size: 13.5))
                        Text(s.detail).font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if let c = s.count { ThingsTag(text: c.formatted()) }
                    Text(s.updated?.relative ?? "").font(.system(size: 11.5)).foregroundStyle(.tertiary)
                }
                .padding(.vertical, 7).padding(.horizontal, 10)
            }
            ModernHeading(title: "Privacy", tint: .green)
            ForEach(privacyText, id: \.self) { Text($0).font(.system(size: 13)).foregroundStyle(.secondary).padding(.horizontal, 10).padding(.bottom, 8) }
        }
    }
    func icon(_ s: SourceStatus.State) -> String {
        switch s { case .ok: return "checkmark.circle.fill"; case .warning: return "exclamationmark.triangle.fill"; case .failed: return "xmark.circle.fill"; case .skipped: return "minus.circle" }
    }
    func tint(_ s: SourceStatus.State) -> Color {
        switch s { case .ok: return .green; case .warning: return .orange; case .failed: return .red; case .skipped: return .secondary }
    }
}
