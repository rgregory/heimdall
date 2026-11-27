import AppKit
import HeimdallCore
import SwiftUI

// MARK: - Overview

struct ModernOverview: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if let r = model.visible {
            let urgent = r.findings.filter { $0.kevCount == 0 && $0.topSeverity >= .high }.sorted { $0.risk.score > $1.risk.score }
            // Exploited and fixable is tonight's work; exploited with nothing to install is not.
            let exploited = r.kevFindings.map { f -> Finding in var f = f; f.vulns = f.vulns.filter(\.isKEV); return f }
            let fixFirst = exploited.filter { !$0.risk.blocked }
            let blocked = exploited.filter { $0.risk.blocked }
            ModernPageFrame(page: .front) {
                verdict(r, urgent: urgent.count)
                if !r.coverageGaps.isEmpty || !r.coverageWarnings.isEmpty {
                    CoverageBanner(gaps: r.coverageGaps.count, total: r.packages.count,
                                   warnings: r.coverageWarnings.count, report: r)
                        .onTapGesture { model.focusUnchecked = true; model.page = .inventory }
                }
                if let message = model.verificationMessage {
                    HStack {
                        Text(message)
                        if !model.scanning { Button("Dismiss") { model.verificationMessage = nil } }
                    }.font(.system(size: 12))
                }
                // The packages behind "minor or unrated" / "no fixed release yet", right under the sentence.
                if r.kevFindings.isEmpty && urgent.isEmpty && !r.findings.isEmpty {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(r.findings) { f in ModernFindingRow(finding: f) }
                    }
                    .padding(.leading, 16).padding(.top, 2)
                }
                if !fixFirst.isEmpty {
                    ModernHeading(title: "Fix First", count: fixFirst.count, tint: .red)
                    ForEach(fixFirst) { f in ModernFindingRow(finding: f) }
                }
                if !blocked.isEmpty {
                    ModernHeading(title: "Blocked", count: blocked.count, tint: .red)
                    Text("Exploited in the wild, but nothing to install yet — the fix is with whoever ships it.")
                        .font(.system(size: 12.5)).foregroundStyle(.secondary).padding(.leading, 36).padding(.bottom, 2)
                    ForEach(blocked) { f in ModernFindingRow(finding: f) }
                }
                if !urgent.isEmpty {
                    ModernHeading(title: "Worth Updating", count: urgent.count, tint: .orange)
                    ForEach(Array(urgent.prefix(5))) { f in ModernFindingRow(finding: f) }
                }
                // Things no release will ever fix. The ones with advisories are already above;
                // this is the standing list, including what nothing has been published against
                // yet — the point being that waiting won't help any of them.
                let dead = r.unmaintained
                if !dead.isEmpty {
                    ModernHeading(title: "Not Maintained", count: dead.count, tint: .brown)
                    Text("No newer version is coming for these. The fix is to remove or replace them.")
                        .font(.system(size: 12.5)).foregroundStyle(.secondary).padding(.leading, 36).padding(.bottom, 2)
                    ForEach(Array(dead.prefix(8))) { p in UnmaintainedRow(package: p, findings: r.findings) }
                    if dead.count > 8 {
                        Button("All \(dead.count) in Inventory") { model.page = .inventory }
                            .buttonStyle(.borderless).font(.system(size: 12, weight: .medium)).padding(.leading, 36).padding(.top, 2)
                    }
                }
                let headlines = model.newsThisWeek
                if !headlines.isEmpty {
                    ModernHeading(title: "In the News", count: headlines.count, tint: .pink)
                    ForEach(Array(headlines.prefix(3))) { s in NewsRow(story: s) }
                    if headlines.count > 3 {
                        Button("All \(headlines.count) stories about this Mac") { model.page = .news }
                            .buttonStyle(.borderless).font(.system(size: 12, weight: .medium)).padding(.leading, 36).padding(.top, 2)
                    }
                }
                ModernHeading(title: "This Mac", tint: .gray)
                ModernPosture(posture: r.posture)
                if let c = model.changes, model.previous != nil, !c.isEmpty {
                    ModernHeading(title: "Since the Last Scan", tint: .teal)
                    ForEach(Array(c.appeared.prefix(5).enumerated()), id: \.offset) { _, x in ChangeRow(finding: x.0, vuln: x.1, resolved: false) }
                    ForEach(Array(c.resolved.prefix(5).enumerated()), id: \.offset) { _, x in ChangeRow(finding: x.0, vuln: x.1, resolved: true, outcome: c.outcome(x.0, x.1)) }
                    ForEach(Array(c.unverified.prefix(5).enumerated()), id: \.offset) { _, x in ChangeRow(finding: x.0, vuln: x.1, resolved: true, outcome: c.outcome(x.0, x.1)) }
                }
            }
        }
    }

    func updateRow(_ p: Package) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "arrow.down.circle").foregroundStyle(.blue).frame(width: 16)
            Text(p.name).font(.system(size: 13.5))
            Text("\(p.version) → \(p.latest ?? "")").font(.system(size: 12.5)).foregroundStyle(.secondary)
            Spacer()
            if let src = p.latestSource { ThingsTag(text: src) }
        }
        .padding(.vertical, 5).padding(.horizontal, 10)
    }

    /// One sentence, Things-quiet: what state the Mac is in.
    func verdict(_ r: ScanReport, urgent: Int) -> some View {
        let kev = r.kevCount, n = r.findings.count
        var icon = "checkmark.circle.fill", tint = Color.green
        var text = "No findings in the completed checks. \(plural(r.packages.count, "package")) inventoried."
        if !r.coverageGaps.isEmpty || !r.coverageWarnings.isEmpty { icon = "exclamationmark.triangle.fill"; tint = .orange }
        if kev > 0 {
            let stuck = r.kevFindings.filter { $0.risk.blocked }.count
            let now = r.kevFindings.count - stuck
            icon = "flame.fill"; tint = .red
            text = now > 0
                ? "\(plural(kev, "exploited flaw")) on this Mac. Fix these first."
                    + (stuck > 0 ? " \(stuck) of them \(stuck == 1 ? "has" : "have") no fix to install yet." : "")
                : "\(plural(kev, "exploited flaw")) on this Mac, but nothing to install yet — each one is waiting on whoever ships it."
        } else if urgent > 0 {
            icon = "exclamationmark.circle.fill"; tint = .orange; text = "Nothing exploited. \(plural(urgent, "package")) with high-severity advisories."
        } else if n > 0 {
            let waiting = r.findings.filter { $0.awaitingRelease == true }.count
            let actionable = n - waiting
            text = actionable > 0
                ? "Nothing urgent. \(plural(actionable, "package")) with minor or unrated advisories" + (waiting > 0 ? "; \(waiting) waiting on an upstream release." : ".")
                : "Nothing to do. \(plural(waiting, "package")) \(waiting == 1 ? "has" : "have") advisories with no fixed release yet."
        }
        return HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: icon).foregroundStyle(tint)
            Text(text).font(.system(size: 15))
            if r.partial { Text("Still checking…").font(.system(size: 13)).foregroundStyle(.tertiary) }
        }
        .padding(.bottom, 4)
    }

    func summaryTiles(_ r: ScanReport) -> some View {
        HStack(spacing: 10) {
            tile("Exploited", r.kevCount, .red, .exploited)
            tile("Critical", r.count(.critical), Severity.critical.tint, .ledger)
            tile("High", r.count(.high), .orange, .ledger)
            tile("Vulnerable", r.findings.count, .blue, .ledger)
            tile("Examined", r.packages.count, .secondary, .inventory)
        }
    }

    func tile(_ label: String, _ n: Int, _ tint: Color, _ page: Page) -> some View {
        Button { model.page = page } label: {
            VStack(alignment: .leading, spacing: 2) {
                Text(n.formatted()).font(.system(size: 24, weight: .semibold)).foregroundStyle(n > 0 ? tint : .secondary)
                Text(label).font(.system(size: 12)).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .background(RoundedRectangle(cornerRadius: 10).fill(Color.primary.opacity(0.04)))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

}

struct ModernPosture: View {
    var posture: SystemPosture
    var body: some View {
        let p = posture
        VStack(alignment: .leading, spacing: 6) {
            row("desktopcomputer", "macOS \(p.osVersion)", p.releasesBehind.isEmpty ? (p.latestInLine == nil ? "Not in Apple's index yet" : "Up to date") : "\(plural(p.releasesBehind.count, "security release")) behind \(p.latestInLine ?? "")", p.releasesBehind.isEmpty ? .green : .red)
            if let s = p.safariVersion {
                let behind = p.safariLatest.map { Version.compare($0, s) > 0 } ?? false
                row("safari", "Safari \(s)", behind ? "Behind \(p.safariLatest!)" : "Up to date", behind ? .orange : .green)
            }
            if !p.releasesBehind.isEmpty {
                Text("Missing " + p.releasesBehind.prefix(5).map { "\($0.version) (\($0.date.shortDay))" }.joined(separator: ", ") + ". Update in System Settings → General → Software Update.")
                    .font(.system(size: 12)).foregroundStyle(.secondary).padding(.leading, 36)
            }
        }
    }
    func row(_ icon: String, _ title: String, _ state: String, _ tint: Color) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon).frame(width: 16).foregroundStyle(.secondary)
            Text(title).font(.system(size: 13.5))
            Spacer()
            ThingsTag(text: state, tint: tint)
        }
        .padding(.vertical, 4).padding(.horizontal, 10)
    }
}
