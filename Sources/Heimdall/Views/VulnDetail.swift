import AppKit
import HeimdallCore
import SwiftUI

/// Full detail for one advisory.
struct VulnDetail: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    var selection: VulnSelection

    var body: some View {
        modernBody
    }

    var v: Vulnerability { selection.vuln }
    var f: Finding { selection.finding }
    var otherIDs: [String] { ([v.id] + v.aliases).filter { $0 != v.headlineID }.uniqued() }
    var lookupURL: URL? {
        URL(string: v.headlineID.hasPrefix("CVE-") ? "https://nvd.nist.gov/vuln/detail/\(v.headlineID)" : "https://osv.dev/vulnerability/\(v.id)")
    }
    var facts: [(String, String)] {
        var out: [(String, String)] = [
            ("Package", "\(f.package.displayName) \(f.package.version)"),
            ("Kind", f.package.ecosystem.title),
            ("Severity", v.severity == .unknown ? "Unrated" : v.severity.title + (v.cvss.map { String(format: " (CVSS %.1f)", $0) } ?? "")),
        ]
        if let e = v.epss { out.append(("EPSS", String(format: "%.1f%% chance of exploitation in 30 days (%.0fth percentile)", e * 100, (v.epssPercentile ?? 0) * 100))) }
        out.append(("Fixed in", v.fixed.isEmpty ? "Not stated" : v.fixed.joined(separator: ", ")))
        if let p = v.published { out.append(("Published", p.shortDay)) }
        out.append(("Matched by", v.source + (v.confidence == .heuristic ? " (inferred from dates)" : " (version range)")))
        if let k = v.kev { out.append(("Exploited per", k.listName)) }
        if let ex = v.publicExploits, !ex.isEmpty { out.append(("Public exploit", ex.joined(separator: ", "))) }
        if !otherIDs.isEmpty { out.append(("Also known as", otherIDs.joined(separator: ", "))) }
        if let vec = v.vector { out.append(("Vector", vec)) }
        if !f.package.location.isEmpty { out.append(("Where", f.package.location)) }
        return out
    }
    static let heuristicNote = "This match is inferred. NVD has no machine-readable affected-version range yet, and the copy on disk is older than the KEV listing. Check the vendor's release notes to confirm."

    // MARK: Modern

    var modernBody: some View {
        VStack(alignment: .leading, spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(spacing: 10) {
                        SeverityRing(severity: v.severity, exploited: v.isKEV)
                        Text(v.headlineID).font(.system(size: 22, weight: .bold)).textSelection(.enabled)
                        if v.isKEV { ThingsTag(text: v.kev?.ransomware == true ? "exploited · ransomware" : "exploited", tint: .red, filled: true) }
                    }
                    Text(v.summary.isEmpty ? "No summary published." : v.summary).font(.system(size: 14)).textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    if let k = v.kev {
                        VStack(alignment: .leading, spacing: 4) {
                            Label(k.source == nil ? "CISA Known Exploited Vulnerability" : "Exploited — \(k.listName)", systemImage: "flame.fill").font(.system(size: 13, weight: .semibold)).foregroundStyle(.red)
                            if !k.vulnerabilityName.isEmpty { Text(k.vulnerabilityName).font(.system(size: 13)) }
                            Text((k.dateAdded.isEmpty ? "" : "Listed \(k.dateAdded)") + (k.dueDate.isEmpty ? "" : " · federal due date \(k.dueDate)") + (k.ransomware ? " · used by ransomware" : ""))
                                .font(.system(size: 12)).foregroundStyle(.secondary)
                            if !k.requiredAction.isEmpty { Text(k.requiredAction).font(.system(size: 12)).foregroundStyle(.secondary) }
                        }
                        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 9).fill(Color.red.opacity(0.07)))
                    }
                    Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                        ForEach(facts, id: \.0) { item in
                            GridRow {
                                Text(item.0).font(.system(size: 12)).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                                Text(item.1).font(.system(size: 12.5)).textSelection(.enabled).lineLimit(3)
                            }
                        }
                    }
                    if v.confidence == .heuristic { Text(Self.heuristicNote).font(.system(size: 12)).foregroundStyle(.secondary) }
                    ModernCommand(text: f.fixHint)
                    if !v.references.isEmpty {
                        Text("References").font(.system(size: 13, weight: .semibold)).padding(.top, 4)
                        ForEach(v.references.prefix(10), id: \.self) { r in
                            if let u = URL(string: r) { Link(r, destination: u).font(.system(size: 12)).lineLimit(1).truncationMode(.middle) }
                        }
                    }
                }
                .padding(24)
            }
            Divider()
            HStack {
                Button(model.isMuted(f, v) ? "Stop Ignoring" : "Ignore for \(f.package.name)") { model.toggleMute(f, v); dismiss() }
                Spacer()
                if let u = lookupURL { Link(v.headlineID.hasPrefix("CVE-") ? "Open on NVD" : "Open on OSV.dev", destination: u) }
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding(14)
        }
        .frame(width: 600, height: 580)
    }
}
