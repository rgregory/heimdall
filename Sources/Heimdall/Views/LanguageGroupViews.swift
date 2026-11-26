import AppKit
import HeimdallCore
import SwiftUI

// MARK: - Language groups

/// Findings that share a parent (a Go binary, a pipx app, a Homebrew-vendored venv) as one unit.
struct ParentGroup: Identifiable {
    var parent: String?
    var findings: [Finding]
    var id: String { (parent ?? "") + "|" + findings.map(\.id).joined(separator: ",") }
    var vulns: [Vulnerability] { findings.flatMap(\.vulns) }
    var kevCount: Int { findings.reduce(0) { $0 + $1.kevCount } }
    var topSeverity: Severity { findings.map(\.topSeverity).max() ?? .unknown }
    var priority: Double { findings.map(\.priority).max() ?? 0 }

    static func group(_ list: [Finding]) -> [ParentGroup] {
        var order: [String] = [], map: [String: [Finding]] = [:]
        for f in list {
            let k = f.package.parent.map { "p:" + $0 } ?? "f:" + f.id
            if map[k] == nil { order.append(k) }
            map[k, default: []].append(f)
        }
        return order.map { k in ParentGroup(parent: k.hasPrefix("p:") ? String(k.dropFirst(2)) : nil, findings: map[k]!.sorted { $0.priority > $1.priority }) }
            .sorted { $0.priority > $1.priority }
    }
}

/// "gitleaks · Go binary · 4 modules" with the worst tags; opens into its modules.
struct ParentGroupRow: View {
    @Environment(AppModel.self) private var model
    var group: ParentGroup
    var parentName: String
    @State private var open = false
    @State private var hover = false

    var body: some View {
        let g = group
        let eco = g.findings.first?.package.ecosystem
        let first = g.findings.first?.package
        let kind = first?.brewFormula != nil ? "Homebrew · Go" : first?.ownerApp.map { "inside \($0)" }
            ?? (eco == .go ? "Go binary" : eco == .pypi ? "Python app" : eco == .npm ? "npm package" : (eco?.title ?? ""))
        let waiting = g.findings.allSatisfy { $0.awaitingRelease == true }
        let modules = g.findings.filter { $0.package.name != "stdlib" }.count
        let hasStdlib = g.findings.contains { $0.package.name == "stdlib" }
        let detail = [modules > 0 ? plural(modules, eco == .go ? "module" : "dependency", eco == .go ? "modules" : "dependencies") : nil,
                      hasStdlib ? "Go toolchain" : nil].compactMap { $0 }.joined(separator: " + ")
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                SeverityRing(severity: g.topSeverity, exploited: g.kevCount > 0)
                Text(parentName).font(.system(size: 13.5, weight: open ? .semibold : .regular)).lineLimit(1)
                Text("\(kind) · \(detail)").font(.system(size: 12.5)).foregroundStyle(.secondary).lineLimit(1)
                Spacer(minLength: 8)
                if g.kevCount > 0 { ThingsTag(text: "exploited", tint: .red, filled: true) }
                else if g.topSeverity != .unknown { ThingsTag(text: g.topSeverity.title.lowercased(), tint: g.topSeverity.tint) }
                if g.vulns.contains(where: \.hasPublicExploit) { RowIcon(symbol: "hammer.fill", tint: .purple, help: "Public exploit code exists") }
                if waiting { RowIcon(symbol: "clock", tint: .secondary, help: first?.brewFormula != nil ? "No fixed build yet" : "No fixed release yet") }
                else if first?.outdated == true { RowIcon(symbol: "arrow.down.circle", tint: .blue, help: "Update available") }
                Text(g.vulns.count.formatted()).font(.system(size: 12)).foregroundStyle(.secondary).frame(minWidth: 22, alignment: .trailing)
            }
            .padding(.vertical, 6).padding(.horizontal, 10)
            .background(RoundedRectangle(cornerRadius: 7).fill(hover && !open ? Color.primary.opacity(0.04) : .clear))
            .contentShape(Rectangle())
            .onHover { hover = $0 }
            .onTapGesture { withAnimation(.snappy(duration: 0.22)) { open.toggle() } }

            if open {
                VStack(alignment: .leading, spacing: 6) {
                    if let f = g.findings.first { FixSteps(steps: f.fixSteps ?? [f.fixHint]) }
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(g.findings) { f in ModernFindingRow(finding: f, showParent: false) }
                    }
                }
                .padding(.leading, 26).padding(.trailing, 6).padding(.bottom, 10)
                .transition(.opacity)
            }
        }
        .background {
            if open {
                RoundedRectangle(cornerRadius: 10).fill(Color(nsColor: .textBackgroundColor))
                    .shadow(color: .black.opacity(0.12), radius: 6, y: 2)
            }
        }
        .padding(.vertical, open ? 6 : 0)
    }
}


/// The verdict above speaks only for what Heimdall could check. When a slice of the Mac was
/// never checked, that is a caveat on the verdict rather than a footnote, so it is drawn as
/// one: a filled band, the share at full size, a bar for how much is missing, and a sentence
/// saying what "not checked" actually means here.
struct CoverageBanner: View {
    var gaps: Int
    var total: Int
    var warnings: Int
    var report: ScanReport
    @State private var hover = false

    var body: some View {
        let all = max(1, total)
        let pct = Int((Double(gaps) / Double(all) * 100).rounded())
        HStack(alignment: .top, spacing: 11) {
            Image(systemName: "exclamationmark.triangle.fill").font(.system(size: 15)).foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    if gaps > 0 {
                        Text("\(pct)%").font(.system(size: 19, weight: .bold)).monospacedDigit().foregroundStyle(.orange)
                        Text("unchecked (\(gaps.formatted()) of \(all.formatted()))")
                            .font(.system(size: 13, weight: .medium))
                    } else {
                        Text(plural(warnings, "source warning")).font(.system(size: 15, weight: .semibold)).foregroundStyle(.orange)
                    }
                }
                if gaps > 0 {
                    GeometryReader { geo in
                        ZStack(alignment: .leading) {
                            Capsule().fill(Color.orange.opacity(0.18))
                            Capsule().fill(Color.orange).frame(width: max(3, geo.size.width * CGFloat(gaps) / CGFloat(all)))
                        }
                    }
                    .frame(height: 5)
                }
                ForEach(lines, id: \.self) { line in
                    Text(line).font(.system(size: 12)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 4)
            Image(systemName: "chevron.right").font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.orange.opacity(0.7)).padding(.top, 3)
        }
        .padding(.horizontal, 14).padding(.vertical, 11)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color.orange.opacity(hover ? 0.18 : 0.12)))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.orange.opacity(0.45), lineWidth: 1))
        .overlay(alignment: .leading) { Capsule().fill(Color.orange).frame(width: 3).padding(.vertical, 6).padding(.leading, 1) }
        .contentShape(Rectangle())
        .onHover { hover = $0 }
        .help("Open the Inventory to see which packages were not checked")
        .padding(.vertical, 4)
    }

    /// Why they were not checked, in the Mac's own numbers — "no mapping" and "lookup failed"
    /// are different problems with different fixes.
    var lines: [String] {
        func count(_ s: PackageCoverage.State) -> Int { report.packages.filter { $0.coverage?.state == s }.count }
        var why: [String] = []
        if count(.noMapping) > 0 { why.append("\(count(.noMapping)) no product mapping") }
        why += PackageCoverage.unavailableBreakdown(report.packages)
        if count(.disabled) > 0 { why.append("\(count(.disabled)) off in Settings") }
        if count(.pending) > 0 { why.append("\(count(.pending)) still checking") }
        var out: [String] = []
        if gaps > 0 {
            out.append("Unknown, not clean." + (why.isEmpty ? "" : " " + why.joined(separator: " · ")))
        }
        if warnings > 0 {
            let names = report.coverageWarnings.prefix(3).map(\.name).joined(separator: ", ")
            out.append("Sources with problems: \(names).")
        }
        return out
    }
}
