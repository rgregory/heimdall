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
}

struct ModernLedger: View {
    @Environment(AppModel.self) private var model
    @State private var sort = [KeyPathComparator(\LedgerRow.kev, order: .reverse), KeyPathComparator(\LedgerRow.severityRank, order: .reverse), KeyPathComparator(\LedgerRow.cvss, order: .reverse)]
    @State private var selection: LedgerRow.ID?

    var body: some View {
        let rows = model.findings(for: .ledger).flatMap { f in f.vulns.map { LedgerRow(finding: f, vuln: $0) } }.sorted(using: sort)
        Table(rows, selection: $selection, sortOrder: $sort) {
            TableColumn("", value: \.kev) { r in
                if r.vuln.isKEV { Image(systemName: "flame.fill").foregroundStyle(.red).help("CISA KEV: exploited in the wild") }
            }
            .width(22)
            TableColumn("Package", value: \.package).width(min: 120, ideal: 180)
            TableColumn("Version", value: \.version) { r in Text(r.version).font(.system(.body, design: .monospaced)).foregroundStyle(.secondary) }
                .width(min: 60, ideal: 90)
            TableColumn("Kind", value: \.ecosystem).width(min: 70, ideal: 100)
            TableColumn("Advisory", value: \.advisory).width(min: 110, ideal: 140)
            TableColumn("Severity", value: \.severityRank) { r in
                HStack(spacing: 5) { Circle().fill(r.vuln.severity.tint).frame(width: 7, height: 7); Text(r.vuln.severity.title) }
            }
            .width(min: 70, ideal: 90)
            TableColumn("CVSS", value: \.cvss) { r in Text(r.cvss >= 0 ? String(format: "%.1f", r.cvss) : "—").monospacedDigit() }.width(44)
            TableColumn("EPSS", value: \.epss) { r in Text(r.epss >= 0 ? String(format: "%.1f%%", r.epss * 100) : "—").monospacedDigit() }.width(54)
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
    }
}

extension Package {
    var latestLabel: String { outdated ? (latest ?? "newer") : (latest == nil ? "" : "current") }
}

struct ModernInventory: View {
    @Environment(AppModel.self) private var model
    @State private var sort = [KeyPathComparator(\Package.name)]
    @State private var kind: Ecosystem?

    var body: some View {
        let vulnerable = Set(model.visible?.findings.map(\.package.id) ?? [])
        let q = model.search.lowercased()
        let pkgs = (model.visible?.packages ?? [])
            .filter { kind == nil || $0.ecosystem == kind }
            .filter { q.isEmpty || $0.name.lowercased().contains(q) || ($0.parent ?? "").lowercased().contains(q) }
            .sorted(using: sort)
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Picker("", selection: $kind) {
                    Text("All kinds").tag(Ecosystem?.none)
                    ForEach(Ecosystem.allCases, id: \.self) { e in Text(e.title).tag(Ecosystem?.some(e)) }
                }
                .labelsHidden().fixedSize()
                Spacer()
                Text(plural(pkgs.count, "package")).foregroundStyle(.secondary)
            }
            .controlSize(.small).padding(.horizontal, 28)
            Table(pkgs, sortOrder: $sort) {
                TableColumn("", value: \.id) { p in SeverityRing(severity: vulnerable.contains(p.id) ? .high : .none, exploited: false).scaleEffect(0.7) }
                    .width(20)
                TableColumn("Name", value: \.name) { p in Text(p.displayName) }.width(min: 140, ideal: 220)
                TableColumn("Version", value: \.version) { p in Text(p.version).font(.system(.body, design: .monospaced)) }.width(min: 70, ideal: 100)
                TableColumn("Kind", value: \.ecosystem.title).width(min: 80, ideal: 110)
                TableColumn("Latest", value: \.latestLabel) { p in Text(p.latestLabel).font(.system(.body, design: .monospaced)).foregroundStyle(p.outdated ? Color.blue : Color.secondary) }
                    .width(min: 60, ideal: 100)
                TableColumn("Found via", value: \.source).width(min: 100, ideal: 160)
                TableColumn("Location", value: \.location) { p in Text(p.location).lineLimit(1).truncationMode(.middle).help(p.location) }
            }
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
