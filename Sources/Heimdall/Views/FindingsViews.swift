import AppKit
import HeimdallCore
import SwiftUI

// MARK: - Findings pages

struct ModernFindingsPage: View {
    @Environment(AppModel.self) private var model
    var page: Page
    @State private var minSeverity: Severity = .unknown
    @State private var kevOnly = false

    var body: some View {
        let list = filtered(model.findings(for: page), minSeverity: minSeverity, kevOnly: kevOnly)
        let groups = Dictionary(grouping: list, by: \.package.ecosystem).sorted { $0.key < $1.key }
        ModernPageFrame(page: page) {
            HStack(spacing: 12) {
                Picker("", selection: $minSeverity) {
                    Text("All severities").tag(Severity.unknown)
                    Text("Low and up").tag(Severity.low)
                    Text("Medium and up").tag(Severity.medium)
                    Text("High and up").tag(Severity.high)
                    Text("Critical only").tag(Severity.critical)
                }
                .labelsHidden().fixedSize()
                if page != .exploited { Toggle("Exploited only", isOn: $kevOnly).toggleStyle(.checkbox) }
                Spacer()
            }
            .controlSize(.small)
            if page == .system, let r = model.visible { ModernPosture(posture: r.posture).padding(.top, 10) }
            if list.isEmpty {
                Text(model.findings(for: page).isEmpty ? "Nothing here. Nice." : "Nothing matches these filters.")
                    .foregroundStyle(.secondary).padding(.top, 30).frame(maxWidth: .infinity)
            }
            ForEach(groups, id: \.key) { g in
                if page == .languages {
                    // One heading per language; modules collapse into the tool that carries them.
                    let units = ParentGroup.group(g.value)
                    ModernHeading(title: g.key.title, count: units.count, tint: page.tint)
                    ForEach(units) { u in
                        if let parent = u.parent, u.findings.count > 1 || g.key == .go { ParentGroupRow(group: u, parentName: parent) }
                        else { ModernFindingRow(finding: u.findings[0]) }
                    }
                } else {
                    if groups.count > 1 || page == .exploited { ModernHeading(title: g.key.title, count: g.value.count, tint: page.tint) }
                    else { Spacer().frame(height: 12) }
                    ForEach(g.value) { f in ModernFindingRow(finding: f) }
                }
            }
        }
    }
}

/// A Things to-do: a ring, the name, tags on the right; click to open it into a card.
struct ModernFindingRow: View {
    @Environment(AppModel.self) private var model
    var finding: Finding
    var showParent = true
    @State private var open = false
    @State private var all = false
    @State private var hover = false

    var body: some View {
        let f = finding, p = f.package
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                SeverityRing(severity: f.topSeverity, exploited: f.kevCount > 0)
                Text(showParent ? (p.parent.map { "\($0) · \(shortModule(p.name))" } ?? p.name) : shortModule(p.name))
                    .font(.system(size: 13.5, weight: open ? .semibold : .regular)).lineLimit(1).truncationMode(.middle)
                Text(shortVersion(p.version)).font(.system(size: 12.5)).foregroundStyle(.secondary).lineLimit(1)
                Spacer(minLength: 8)
                HStack(spacing: 6) {
                    if f.vulns.contains(where: \.hasPublicExploit) { RowIcon(symbol: "hammer.fill", tint: .purple, help: "Public exploit code exists") }
                    if model.newsPackageIDs.contains(p.id) { RowIcon(symbol: "newspaper.fill", tint: .pink, help: "In the news this week") }
                    if let e = p.exposure, e.listening {
                        RowIcon(symbol: "antenna.radiowaves.left.and.right", tint: .orange,
                                help: "Listening on " + e.ports.map(String.init).joined(separator: ", "))
                    } else if p.exposure?.running == true {
                        RowIcon(symbol: "play.circle", tint: .orange, help: "Running right now")
                    } else if p.exposure?.autostart == true {
                        RowIcon(symbol: "power", tint: .orange, help: "Started by launchd")
                    }
                    if f.risk.abandoned { RowIcon(symbol: "trash.slash", tint: .brown, help: p.maintenance?.reason ?? "No fix is coming") }
                    if f.awaitingRelease == true { RowIcon(symbol: "clock", tint: .secondary, help: "No fixed release yet") }
                    else if p.outdated { RowIcon(symbol: "arrow.down.circle", tint: .blue, help: p.latest.map { "Update available: \($0)" } ?? "Update available") }
                }
                if let d = f.ageDays, d >= 7 { ThingsTag(text: "\(d)d", tint: .secondary) }
                if f.kevCount > 0 { ThingsTag(text: f.ransomware ? "exploited · ransomware" : "exploited", tint: .red, filled: true) }
                else if f.topSeverity != .unknown { ThingsTag(text: f.topSeverity.title.lowercased(), tint: f.topSeverity.tint) }
                Text(f.vulns.count.formatted()).font(.system(size: 12)).foregroundStyle(.secondary).frame(minWidth: 22, alignment: .trailing)
            }
            .padding(.vertical, 6).padding(.horizontal, 10)
            .background(RoundedRectangle(cornerRadius: 7).fill(hover && !open ? Color.primary.opacity(0.04) : .clear))
            .contentShape(Rectangle())
            .onHover { hover = $0 }
            .onTapGesture { withAnimation(.snappy(duration: 0.22)) { open.toggle() } }
            .contextMenu {
                Button("Ignore \(p.name)") { model.toggleMute(p) }
                Button("Verify fix (rescan)") { model.verifyFix(f) }.disabled(model.scanning)
                Button("Copy Fix Command") { model.copy(commandPart(f.fixHint)) }
                if !p.location.isEmpty { Button("Reveal in Finder") { NSWorkspace.shared.selectFile(p.location, inFileViewerRootedAtPath: "") } }
            }

            if open {
                VStack(alignment: .leading, spacing: 10) {
                    if !f.risk.factors.isEmpty {
                        Text("Ranked here because: " + f.risk.factors.joined(separator: " · "))
                            .font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                    Text([p.ecosystem.title, p.source, p.location].filter { !$0.isEmpty }.joined(separator: " · "))
                        .font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(2).truncationMode(.middle)
                    if let m = p.maintenance {
                        Label {
                            Text("\(m.state.title) — \(m.reason) (\(m.source))").font(.system(size: 12))
                        } icon: {
                            Image(systemName: "trash.slash").font(.system(size: 11))
                        }
                        .foregroundStyle(m.terminal ? Color.brown : .secondary)
                    }
                    if let e = p.exposure {
                        Text("On this Mac: " + e.summary + (e.notes.isEmpty ? "" : " — " + e.notes.joined(separator: "; ")))
                            .font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(3).truncationMode(.middle)
                    }
                    if let first = f.firstSeen, let d = f.ageDays {
                        Text(d == 0 ? "First seen in today's scan." : "Open here for \(plural(d, "day")), since \(first.formatted(date: .abbreviated, time: .omitted)).")
                            .font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                    FixSteps(steps: f.fixSteps ?? [f.fixHint])
                    Button("Verify fix (rescan)") { model.verifyFix(f) }.disabled(model.scanning)
                    if let message = model.verificationMessage { Text(message).font(.caption).foregroundStyle(.secondary) }
                    VStack(spacing: 0) {
                        ForEach(f.vulns.prefix(all ? f.vulns.count : 8)) { v in ModernVulnRow(finding: f, vuln: v) }
                    }
                    if f.vulns.count > 8 {
                        Button(all ? "Show fewer" : "Show all \(f.vulns.count)") { withAnimation { all.toggle() } }
                            .buttonStyle(.borderless).font(.system(size: 12, weight: .medium))
                    }
                }
                .padding(.horizontal, 36).padding(.bottom, 14).padding(.top, 2)
                .transition(.opacity)
            }
        }
        .background {
            if open {
                RoundedRectangle(cornerRadius: 10)
                    .fill(Color(nsColor: .textBackgroundColor))
                    .shadow(color: .black.opacity(0.14), radius: 8, y: 2)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.primary.opacity(0.06)))
            }
        }
        .padding(.vertical, open ? 8 : 0)
    }
}

struct ModernVulnRow: View {
    @Environment(AppModel.self) private var model
    var finding: Finding
    var vuln: Vulnerability
    @State private var hover = false

    var body: some View {
        let v = vuln
        HStack(spacing: 8) {
            Circle().fill(v.severity.tint).frame(width: 7, height: 7)
            Text(v.headlineID).font(.system(size: 12, weight: .medium)).frame(width: 140, alignment: .leading)
            if v.isKEV { Image(systemName: "flame.fill").font(.system(size: 10)).foregroundStyle(.red).help("Exploited: \(v.kev?.listName ?? "")") }
            if v.hasPublicExploit { Image(systemName: "hammer.fill").font(.system(size: 10)).foregroundStyle(.purple).help("Public exploit: " + (v.publicExploits ?? []).joined(separator: ", ")) }
            Text(v.summary.isEmpty ? "No summary" : v.summary).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
            Spacer(minLength: 6)
            if let c = v.cvss { Text(String(format: "%.1f", c)).font(.system(size: 11.5).monospacedDigit()).foregroundStyle(.secondary) }
            Image(systemName: "chevron.right").font(.system(size: 9, weight: .semibold)).foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4).padding(.horizontal, 6)
        .background(RoundedRectangle(cornerRadius: 5).fill(hover ? Color.accentColor.opacity(0.08) : .clear))
        .contentShape(Rectangle())
        .onHover { hover = $0 }
        .onTapGesture { model.selectedVuln = VulnSelection(finding: finding, vuln: v) }
        .contextMenu {
            Button("Ignore \(v.headlineID) for \(finding.package.name)") { model.toggleMute(finding, v) }
            Button("Copy \(v.headlineID)") { model.copy(v.headlineID) }
        }
    }
}

// MARK: - Search

/// Toolbar search across everything Heimdall read, from any page: vulnerable packages,
/// advisories by ID or text, and installed software with no known advisories.
struct ModernSearchResults: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let q = model.search.trimmingCharacters(in: .whitespaces).lowercased()
        let r = model.visible
        let vulnerable = model.findings(for: .ledger)
        let vulnIDs = Set((r?.findings ?? []).map(\.package.id))
        let installed = (r?.packages ?? []).filter { p in
            !vulnIDs.contains(p.id) && [p.name, p.parent ?? "", p.bundleID ?? "", p.cask ?? "", p.browser ?? ""].contains { $0.lowercased().contains(q) }
        }
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 10) {
                    Image(systemName: "magnifyingglass").font(.system(size: 20, weight: .semibold)).foregroundStyle(.secondary)
                    Text("“\(model.search)”").font(.system(size: 26, weight: .bold))
                }
                Text("\(plural(vulnerable.count, "vulnerable package")), \(plural(installed.count, "other installed match", "other installed matches"))")
                    .font(.system(size: 13)).foregroundStyle(.secondary).padding(.top, 6)

                if !vulnerable.isEmpty {
                    ModernHeading(title: "With Advisories", count: vulnerable.count, tint: .red)
                    ForEach(vulnerable) { f in ModernFindingRow(finding: f) }
                }
                if !installed.isEmpty {
                    ModernHeading(title: "Installed, No Known Advisories", count: installed.count, tint: .green)
                    ForEach(installed.prefix(200)) { p in InstalledRow(package: p) }
                }
                if vulnerable.isEmpty && installed.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Nothing Heimdall read matches “\(model.search)”.").font(.system(size: 15))
                        Text("It reads apps, Homebrew, Python, npm, cargo, Ruby gems, Go binaries and browser extensions. Tools that ship with macOS (like /usr/bin/ssh or the system PHP) are covered by the macOS checks, not listed one by one.")
                            .font(.system(size: 13)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.top, 24)
                }
            }
            .frame(maxWidth: 760, alignment: .leading)
            .padding(.horizontal, 40).padding(.top, 28).padding(.bottom, 40)
            .frame(maxWidth: .infinity)
        }
    }
}

/// One unmaintained package: what it is, who said so, and whether anything is published against
/// it yet. A clean one still belongs on the list — it just hasn't been found out yet.
struct UnmaintainedRow: View {
    var package: Package
    var findings: [Finding]

    var body: some View {
        let p = package
        let open = findings.filter { $0.package.name == p.name && $0.package.ecosystem == p.ecosystem }
        let vulns = open.reduce(0) { $0 + $1.vulns.count }
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: "trash.slash").foregroundStyle(.brown).frame(width: 16)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    Text(p.displayName).font(.system(size: 13.5)).lineLimit(1)
                    Text(p.version).font(.system(size: 12.5)).foregroundStyle(.secondary)
                }
                Text(p.maintenance?.reason ?? "").font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer(minLength: 8)
            if vulns > 0 { ThingsTag(text: plural(vulns, "advisory", "advisories"), tint: .red) }
            else { ThingsTag(text: "nothing published yet") }
            ThingsTag(text: p.maintenance?.state.title.lowercased() ?? "", tint: .brown)
        }
        .padding(.vertical, 5).padding(.horizontal, 10)
        .help(p.location)
    }
}

struct InstalledRow: View {
    var package: Package
    var body: some View {
        let p = package
        HStack(spacing: 10) {
            Image(systemName: p.coverage?.state == .checked ? "checkmark.circle" : "questionmark.circle")
                .foregroundStyle(p.coverage?.state == .checked ? Color.green : Color.orange).frame(width: 16)
            Text(p.displayName).font(.system(size: 13.5)).lineLimit(1)
            Text(p.version).font(.system(size: 12.5)).foregroundStyle(.secondary).lineLimit(1)
            Spacer(minLength: 8)
            if let e = p.exposure, e.listening { ThingsTag(text: "listening " + e.ports.map(String.init).joined(separator: ","), tint: .orange) }
            else if p.exposure?.running == true { ThingsTag(text: "running", tint: .orange) }
            if let m = p.maintenance { ThingsTag(text: m.state.title.lowercased(), tint: m.terminal ? .brown : .secondary) }
            if p.outdated { ThingsTag(text: p.latest.map { "update → \($0)" } ?? "update ready", tint: .blue) }
            ThingsTag(text: p.coverage?.state.title ?? "Coverage unknown", tint: p.coverage?.state == .checked ? .secondary : .orange)
            ThingsTag(text: p.ecosystem.title)
        }
        .padding(.vertical, 5).padding(.horizontal, 10)
        .help(p.location)
    }
}

/// A "Since the Last Scan" line that opens into a card: what it is, how bad, and the fix.
struct ChangeRow: View {
    @Environment(AppModel.self) private var model
    var finding: Finding
    var vuln: Vulnerability
    var resolved: Bool
    var outcome: RemediationOutcome? = nil
    @State private var open = false
    @State private var hover = false

    var body: some View {
        let f = finding, v = vuln
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: resolved ? (outcome == .fixed || outcome == .removed ? "checkmark.circle" : "questionmark.circle") : "plus.circle").foregroundStyle(resolved ? (outcome == .fixed || outcome == .removed ? Color.green : Color.orange) : Color.red)
                Text(f.package.displayName).font(.system(size: 13.5, weight: open ? .semibold : .regular))
                Text(v.headlineID).font(.system(size: 12.5)).foregroundStyle(.secondary)
                if let outcome { ThingsTag(text: outcome.rawValue, tint: outcome == .fixed || outcome == .removed ? .green : .orange) }
                if v.isKEV { ThingsTag(text: "exploited", tint: .red, filled: true) }
                if v.hasPublicExploit { ThingsTag(text: "public exploit", tint: .purple) }
                Spacer(minLength: 8)
                if v.severity != .unknown { ThingsTag(text: v.severity.title.lowercased(), tint: v.severity.tint) }
                Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(.tertiary)
                    .rotationEffect(.degrees(open ? 90 : 0))
            }
            .padding(.vertical, 6).padding(.horizontal, 10)
            .background(RoundedRectangle(cornerRadius: 7).fill(hover && !open ? Color.primary.opacity(0.04) : .clear))
            .contentShape(Rectangle())
            .onHover { hover = $0 }
            .onTapGesture { withAnimation(.snappy(duration: 0.22)) { open.toggle() } }

            if open {
                VStack(alignment: .leading, spacing: 10) {
                    Text(v.summary.isEmpty ? "No summary published." : v.summary)
                        .font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 14) {
                        fact("Installed", f.package.version)
                        fact("Fixed in", firstFix(v, above: f.package.version))
                        if let c = v.cvss { fact("CVSS", String(format: "%.1f", c)) }
                        if let e = v.epss { fact("EPSS", String(format: "%.1f%%", e * 100)) }
                        fact("Source", v.source)
                    }
                    if resolved {
                        Text(outcome?.rawValue ?? "Fix unconfirmed")
                            .font(.system(size: 12.5)).foregroundStyle(.secondary)
                    } else {
                        ModernCommand(text: f.fixHint)
                    }
                    HStack(spacing: 14) {
                        Button("Full details…") { model.selectedVuln = VulnSelection(finding: f, vuln: v) }
                        if !resolved { Button("Ignore") { model.toggleMute(f, v) } }
                    }
                    .buttonStyle(.borderless).font(.system(size: 12, weight: .medium))
                }
                .padding(.horizontal, 36).padding(.bottom, 14).padding(.top, 2)
                .transition(.opacity)
            }
        }
        .background {
            if open {
                RoundedRectangle(cornerRadius: 10)
                    .fill(Color(nsColor: .textBackgroundColor))
                    .shadow(color: .black.opacity(0.14), radius: 8, y: 2)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.primary.opacity(0.06)))
            }
        }
        .padding(.vertical, open ? 8 : 0)
    }

    func fact(_ k: String, _ v: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(k).font(.system(size: 10.5, weight: .medium)).foregroundStyle(.secondary)
            Text(v).font(.system(size: 12.5)).lineLimit(1)
        }
    }
}
