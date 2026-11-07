import AppKit
import HeimdallCore
import SwiftUI

/// Things-style: tinted sidebar, a big title with its icon, quiet rows that open into cards.
struct ModernShell: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            // Rows are plain buttons on model.page (List selection didn't take clicks here).
            List {
                sidebarRow(.front, nil)
                sidebarRow(.exploited, model.visible?.kevCount)
                sidebarRow(.news, model.visible?.news.map { list in list.filter { $0.relevance != .general && ($0.published ?? .distantPast) > Date().addingTimeInterval(-7 * 86400) }.count })
                Section {
                    ForEach([Page.system, .apps, .homebrew, .languages]) { p in
                        sidebarRow(p, p.desk.flatMap { model.visible?.findings(in: $0).count })
                    }
                }
                Section {
                    sidebarRow(.ledger, nil)
                    sidebarRow(.inventory, nil)
                    sidebarRow(.sources, nil)
                }
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 200, ideal: 230)
            .safeAreaInset(edge: .bottom) { scanFooter }
        } detail: {
            let page = model.page
            Group {
                if model.visible == nil { ModernEmpty() }
                else if !model.search.trimmingCharacters(in: .whitespaces).isEmpty { ModernSearchResults() }
                else {
                    switch page {
                    case .front: ModernOverview()
                    case .ledger: ModernPageFrame(page: .ledger, scrolls: false) { ModernLedger() }
                    case .inventory: ModernPageFrame(page: .inventory, scrolls: false) { ModernInventory() }
                    case .sources: ModernPageFrame(page: .sources) { ModernSources() }
                    case .exploited: ExploitedTimeline()
                    case .news: NewsPage()
                    default: ModernFindingsPage(page: page)
                    }
                }
            }
            .id(page)   // fresh page state (filters, scroll) per section
            .background(Ink.paper2)
            .navigationTitle("")
        }
        .searchable(text: $model.search, placement: .toolbar, prompt: "Package or CVE")
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button { model.scan() } label: { Label("Scan", systemImage: "arrow.clockwise") }
                    .disabled(model.scanning).help("Scan again (⌘R)")
                Menu {
                    Button("Report as JSON…") { model.export(csv: false) }
                    Button("Advisories as CSV…") { model.export(csv: true) }
                } label: { Label("Export", systemImage: "square.and.arrow.up") }
                    .disabled(model.report == nil)
            }
        }
    }

    func sidebarRow(_ p: Page, _ count: Int?) -> some View {
        SidebarRow(page: p, count: count, selected: model.page == p) { model.page = p }
            .listRowInsets(EdgeInsets(top: 1, leading: 6, bottom: 1, trailing: 6))
    }

    @ViewBuilder var scanFooter: some View {
        VStack(alignment: .leading, spacing: 4) {
            if model.scanning {
                ProgressView(value: model.progress).controlSize(.small)
                Text(model.stage).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            } else if let r = model.report {
                Text("Scanned \(r.generated.relative)").font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// A sidebar row drawn like the native selection: accent pill, white text and icon.
struct SidebarRow: View {
    var page: Page
    var count: Int?
    var selected: Bool
    var action: () -> Void
    @Environment(\.controlActiveState) private var active

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: page.symbol)
                    .font(.system(size: 14))
                    .foregroundStyle(selected ? Color.white : page.tint)
                    .frame(width: 20)
                Text(page.title)
                    .font(.system(size: 13, weight: selected ? .semibold : .regular))
                    .foregroundStyle(selected ? Color.white : Color.primary)
                Spacer(minLength: 4)
                if let count, count > 0 {
                    Text(count.formatted())
                        .font(.system(size: 11, weight: .medium)).monospacedDigit()
                        .foregroundStyle(selected ? Color.white.opacity(0.9) : Color.secondary)
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(Capsule().fill(selected ? Color.white.opacity(0.22) : Color.primary.opacity(0.07)))
                }
            }
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(RoundedRectangle(cornerRadius: 7).fill(selected ? (active == .inactive ? Color.gray.opacity(0.55) : Color.accentColor) : Color.clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// Title block shared by every page: coloured icon, bold title, quiet note.
struct ModernPageFrame<Content: View>: View {
    var page: Page
    var scrolls = true
    @ViewBuilder var content: Content

    var body: some View {
        let header = VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Image(systemName: page.symbol).font(.system(size: 22, weight: .semibold)).foregroundStyle(page.tint)
                Text(page.title).font(.system(size: 26, weight: .bold))
            }
            Text(pageSubtitle(page)).font(.system(size: 13)).foregroundStyle(.secondary)
        }
        .padding(.bottom, 14)

        if scrolls {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) { header; content }
                    .frame(maxWidth: 760, alignment: .leading)
                    .padding(.horizontal, 40).padding(.top, 28).padding(.bottom, 40)
                    .frame(maxWidth: .infinity)
            }
        } else {
            VStack(alignment: .leading, spacing: 0) { header.padding(.horizontal, 28).padding(.top, 24); content }
        }
    }
}

struct ModernEmpty: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "eye").font(.system(size: 42, weight: .light)).foregroundStyle(.blue)
            Text(model.scanning ? "Looking around…" : "No scan yet").font(.title2.bold())
            Text(model.scanning ? model.stage : "Heimdall reads only what your account can read.").foregroundStyle(.secondary)
            if model.scanning { ProgressView(value: model.progress).frame(width: 240) }
            else { Button("Scan Now") { model.scan() }.controlSize(.large).buttonStyle(.borderedProminent) }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Things' heading: bold, tinted, with a hairline under it.
struct ModernHeading: View {
    var title: String
    var count: Int? = nil
    var tint: Color = .blue
    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text(title).font(.system(size: 13.5, weight: .semibold)).foregroundStyle(tint)
                Spacer()
                if let count { Text(count.formatted()).font(.system(size: 12)).foregroundStyle(.secondary) }
            }
            Rectangle().fill(tint.opacity(0.25)).frame(height: 1)
        }
        .padding(.top, 22).padding(.bottom, 4)
    }
}

// MARK: - Overview

struct ModernOverview: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if let r = model.visible {
            let urgent = r.findings.filter { $0.kevCount == 0 && $0.topSeverity >= .high }
            ModernPageFrame(page: .front) {
                verdict(r, urgent: urgent.count)
                // The packages behind "minor or unrated" / "no fixed release yet", right under the sentence.
                if r.kevFindings.isEmpty && urgent.isEmpty && !r.findings.isEmpty {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(r.findings) { f in ModernFindingRow(finding: f) }
                    }
                    .padding(.leading, 16).padding(.top, 2)
                }
                if !r.kevFindings.isEmpty {
                    ModernHeading(title: "Fix First", count: r.kevFindings.count, tint: .red)
                    ForEach(r.kevFindings.map { f -> Finding in var f = f; f.vulns = f.vulns.filter(\.isKEV); return f }) { f in
                        ModernFindingRow(finding: f)
                    }
                }
                if !urgent.isEmpty {
                    ModernHeading(title: "Worth Updating", count: urgent.count, tint: .orange)
                    ForEach(Array(urgent.prefix(5))) { f in ModernFindingRow(finding: f) }
                }
                let stale = r.outdatedPackages.filter { p in !r.findings.contains { $0.package.id == p.id } }
                if !stale.isEmpty {
                    ModernHeading(title: "Updates Available", count: stale.count, tint: .blue)
                    ForEach(Array(stale.prefix(6))) { p in updateRow(p) }
                    if stale.count > 6 {
                        Button("Show all \(stale.count) in Inventory") { model.page = .inventory }
                            .buttonStyle(.borderless).font(.system(size: 12, weight: .medium)).padding(.leading, 36).padding(.top, 2)
                    }
                }
                let headlines = (r.news ?? []).filter { $0.relevance != .general && ($0.published ?? .distantPast) > Date().addingTimeInterval(-7 * 86400) }
                if !headlines.isEmpty {
                    ModernHeading(title: "In the News", count: headlines.count, tint: .pink)
                    ForEach(Array(headlines.prefix(3))) { n in NewsRow(item: n) }
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
                    ForEach(Array(c.resolved.prefix(5).enumerated()), id: \.offset) { _, x in ChangeRow(finding: x.0, vuln: x.1, resolved: true) }
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
        var text = "All clear. \(plural(r.packages.count, "package")) read, nothing published against them."
        if kev > 0 {
            icon = "flame.fill"; tint = .red; text = "\(plural(kev, "exploited flaw")) on this Mac. Fix these first."
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
    @State private var open = false
    @State private var all = false
    @State private var hover = false

    var body: some View {
        let f = finding, p = f.package
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                SeverityRing(severity: f.topSeverity, exploited: f.kevCount > 0)
                Text(p.name).font(.system(size: 13.5, weight: open ? .semibold : .regular)).lineLimit(1)
                Text(p.version).font(.system(size: 12.5)).foregroundStyle(.secondary).lineLimit(1)
                if let parent = p.parent { Text("in \(parent)").font(.system(size: 12)).foregroundStyle(.tertiary).lineLimit(1) }
                Spacer(minLength: 8)
                if f.kevCount > 0 { ThingsTag(text: f.ransomware ? "exploited · ransomware" : "exploited", tint: .red, filled: true) }
                if f.topSeverity != .unknown { ThingsTag(text: f.topSeverity.title.lowercased(), tint: f.topSeverity.tint) }
                if f.vulns.contains(where: \.hasPublicExploit) { ThingsTag(text: "public exploit", tint: .purple) }
                if f.awaitingRelease == true { ThingsTag(text: "no fix released yet") }
                if model.newsPackageIDs.contains(p.id) { ThingsTag(text: "in the news", tint: .pink) }
                if p.outdated { ThingsTag(text: p.latest.map { "update → \($0)" } ?? "update ready", tint: .blue) }
                Text(f.vulns.count.formatted()).font(.system(size: 12)).foregroundStyle(.secondary).frame(minWidth: 22, alignment: .trailing)
            }
            .padding(.vertical, 6).padding(.horizontal, 10)
            .background(RoundedRectangle(cornerRadius: 7).fill(hover && !open ? Color.primary.opacity(0.04) : .clear))
            .contentShape(Rectangle())
            .onHover { hover = $0 }
            .onTapGesture { withAnimation(.snappy(duration: 0.22)) { open.toggle() } }
            .contextMenu {
                Button("Ignore \(p.name)") { model.toggleMute(p) }
                Button("Copy Fix Command") { model.copy(commandPart(f.fixHint)) }
                if !p.location.isEmpty { Button("Reveal in Finder") { NSWorkspace.shared.selectFile(p.location, inFileViewerRootedAtPath: "") } }
            }

            if open {
                VStack(alignment: .leading, spacing: 10) {
                    Text([p.ecosystem.title, p.source, p.location].filter { !$0.isEmpty }.joined(separator: " · "))
                        .font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(2).truncationMode(.middle)
                    ModernCommand(text: f.fixHint)
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

struct InstalledRow: View {
    var package: Package
    var body: some View {
        let p = package
        HStack(spacing: 10) {
            Image(systemName: "checkmark.circle").foregroundStyle(.green).frame(width: 16)
            Text(p.displayName).font(.system(size: 13.5)).lineLimit(1)
            Text(p.version).font(.system(size: 12.5)).foregroundStyle(.secondary).lineLimit(1)
            Spacer(minLength: 8)
            if p.outdated { ThingsTag(text: p.latest.map { "update → \($0)" } ?? "update ready", tint: .blue) }
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
    @State private var open = false
    @State private var hover = false

    var body: some View {
        let f = finding, v = vuln
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: resolved ? "checkmark.circle" : "plus.circle").foregroundStyle(resolved ? Color.green : Color.red)
                Text(f.package.displayName).font(.system(size: 13.5, weight: open ? .semibold : .regular))
                Text(v.headlineID).font(.system(size: 12.5)).foregroundStyle(.secondary)
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
                        Label("No longer applies — updated, removed or no longer matched since the last scan.", systemImage: "checkmark.seal")
                            .font(.system(size: 12.5)).foregroundStyle(.green)
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

// MARK: - Exploited timeline

/// CISA KEV listings over time: "This Mac" shows only listings for software installed here
/// (open ones in red, unaffected versions in green); "Everything" shows the whole feed.
struct ExploitedTimeline: View {
    @Environment(AppModel.self) private var model
    @AppStorage("timelineScope") private var everything = false
    @AppStorage("timelineDays") private var days = 90

    var body: some View {
        let r = model.visible
        let cutoff = Date().addingTimeInterval(-Double(days) * 86400)
        let q = model.search.lowercased()
        let all = (r?.timeline ?? []).filter { ($0.date ?? .distantPast) >= cutoff }
            .filter { q.isEmpty || "\($0.cve) \($0.vendor) \($0.product) \($0.name)".lowercased().contains(q) }
        let mine = all.filter { $0.relevance != .elsewhere }
        let shown = everything ? all : mine
        let openNow = r?.kevFindings ?? []
        let months = Dictionary(grouping: shown) { String($0.added.prefix(7)) }.sorted { $0.key > $1.key }

        ModernPageFrame(page: .exploited) {
            HStack(spacing: 12) {
                Picker("", selection: $everything) {
                    Text("This Mac").tag(false)
                    Text("Everything").tag(true)
                }
                .pickerStyle(.segmented).labelsHidden().fixedSize()
                Picker("", selection: $days) {
                    Text("30 days").tag(30)
                    Text("90 days").tag(90)
                    Text("12 months").tag(365)
                }
                .labelsHidden().fixedSize()
                Spacer()
                Text(everything ? "\(all.count) listed · \(mine.count) touch this Mac" : "\(mine.count) of \(all.count) listings touch this Mac")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            }
            .controlSize(.small)

            if !openNow.isEmpty {
                ModernHeading(title: "Open on This Mac", count: openNow.count, tint: .red)
                ForEach(openNow.map { f -> Finding in var f = f; f.vulns = f.vulns.filter(\.isKEV); return f }) { f in ModernFindingRow(finding: f) }
            }

            if r?.timeline == nil {
                Text("Rescan (⌘R) to build the timeline.").foregroundStyle(.secondary).padding(.top, 24)
            } else if shown.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text(everything ? "Nothing added to CISA's list in this period." : "Nothing CISA listed in the last \(days) days touches software on this Mac.")
                        .font(.system(size: 14))
                    if !everything { Text("Switch to Everything to see what's being exploited elsewhere.").font(.system(size: 12.5)).foregroundStyle(.secondary) }
                }
                .padding(.top, 24)
            }
            ForEach(months, id: \.key) { m in
                ModernHeading(title: monthTitle(m.key), count: m.value.count, tint: .red)
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(TimelineGroup.group(m.value)) { g in TimelineRow(group: g, dimmed: everything && g.relevance == .elsewhere) }
                }
            }
        }
    }

    func monthTitle(_ ym: String) -> String {
        let f = DateFormatter(); f.dateFormat = "yyyy-MM"
        guard let d = f.date(from: ym) else { return ym }
        return d.formatted(.dateTime.month(.wide).year())
    }
}

/// Same day, same product: one line with all its CVEs (Plex ×4 on Oct 19 → one row).
struct TimelineGroup: Identifiable {
    var entries: [TimelineEntry]
    var id: String { entries.map(\.cve).joined(separator: ",") }
    var first: TimelineEntry { entries[0] }
    var relevance: TimelineEntry.Relevance {
        if entries.contains(where: { $0.relevance == .affected }) { return .affected }
        if entries.contains(where: { $0.relevance == .installed }) { return .installed }
        return .elsewhere
    }
    var ransomware: Bool { entries.contains(where: { $0.ransomware }) }
    var packages: [String] { entries.flatMap(\.packages).uniqued() }
    var fix: String? { entries.compactMap(\.fix).first }

    static func group(_ list: [TimelineEntry]) -> [TimelineGroup] {
        var order: [String] = [], map: [String: [TimelineEntry]] = [:]
        for e in list {
            let k = "\(e.added)|\(e.vendor)|\(e.product)"
            if map[k] == nil { order.append(k) }
            map[k, default: []].append(e)
        }
        return order.map { TimelineGroup(entries: map[$0]!.sorted { $0.cve < $1.cve }) }
    }
}

struct TimelineRow: View {
    @Environment(AppModel.self) private var model
    var group: TimelineGroup
    var dimmed: Bool
    @State private var open = false
    @State private var hover = false

    var node: some View {
        ZStack {
            switch group.relevance {
            case .affected: Circle().fill(Color.red).frame(width: 11, height: 11)
            case .installed: Circle().strokeBorder(Color.green, lineWidth: 2).frame(width: 11, height: 11).background(Circle().fill(Ink.paper2))
            case .elsewhere: Circle().fill(Color.secondary.opacity(0.45)).frame(width: 7, height: 7)
            }
        }
        .frame(width: 22, height: 22)
    }

    /// "SSRF ×2 · Path traversal · URI schemes" — the vulnerability names, shortened and counted.
    var subtitle: String {
        let names = group.entries.map { n -> String in
            var t = n.name
            for p in ["\(n.vendor) \(n.product) ", "\(n.product) "] where t.hasPrefix(p) { t = String(t.dropFirst(p.count)) }
            return t.replacingOccurrences(of: " Vulnerability", with: "")
        }
        var counts: [String: Int] = [:], order: [String] = []
        for n in names { if counts[n] == nil { order.append(n) }; counts[n, default: 0] += 1 }
        return order.map { counts[$0]! > 1 ? "\($0) ×\(counts[$0]!)" : $0 }.joined(separator: " · ")
    }

    var body: some View {
        let g = group, e = group.first
        HStack(alignment: .top, spacing: 0) {
            Text(e.date?.formatted(.dateTime.month(.abbreviated).day()) ?? e.added)
                .font(.system(size: 12).monospacedDigit()).foregroundStyle(.secondary)
                .frame(width: 52, alignment: .trailing).padding(.top, 9)
            ZStack(alignment: .top) {
                Rectangle().fill(Color.primary.opacity(0.12)).frame(width: 2).frame(maxHeight: .infinity)
                node.padding(.top, 5)
            }
            .frame(width: 30)
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("\(e.vendor) \(e.product)").font(.system(size: 13.5, weight: g.relevance == .elsewhere ? .regular : .semibold)).lineLimit(1)
                    if g.entries.count == 1 { Text(e.cve).font(.system(size: 12)).foregroundStyle(.secondary) }
                    else { ThingsTag(text: "\(g.entries.count) CVEs") }
                    if g.ransomware { ThingsTag(text: "ransomware", tint: .red) }
                    Spacer(minLength: 6)
                    relevanceTag
                }
                Text(subtitle).font(.system(size: 12.5)).foregroundStyle(.secondary).lineLimit(open ? nil : 1)
                if open { detail.padding(.top, 4) }
            }
            .padding(.vertical, 7).padding(.horizontal, 10)
            .background(RoundedRectangle(cornerRadius: 8).fill(open ? Color(nsColor: .textBackgroundColor) : (hover ? Color.primary.opacity(0.04) : .clear)))
            .shadow(color: .black.opacity(open ? 0.12 : 0), radius: 6, y: 2)
            .padding(.vertical, 2)
        }
        .opacity(dimmed ? 0.6 : 1)
        .contentShape(Rectangle())
        .onHover { hover = $0 }
        .onTapGesture { withAnimation(.snappy(duration: 0.22)) { open.toggle() } }
    }

    @ViewBuilder var relevanceTag: some View {
        switch group.relevance {
        case .affected: ThingsTag(text: "affects " + (group.packages.first ?? "this Mac"), tint: .red, filled: true)
        case .installed: ThingsTag(text: "installed · not a vulnerable version", tint: .green)
        case .elsewhere: EmptyView()
        }
    }

    @ViewBuilder var detail: some View {
        let g = group
        VStack(alignment: .leading, spacing: 8) {
            // One line per CVE in the group.
            VStack(alignment: .leading, spacing: 3) {
                ForEach(g.entries) { e in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Circle().fill(e.relevance == .affected ? Color.red : Color.secondary.opacity(0.5)).frame(width: 6, height: 6)
                        Link(e.cve, destination: URL(string: "https://nvd.nist.gov/vuln/detail/\(e.cve)")!)
                            .font(.system(size: 12, weight: .medium)).frame(width: 128, alignment: .leading)
                        Text(e.name).font(.system(size: 12.5)).lineLimit(1)
                        if e.ransomware { ThingsTag(text: "ransomware", tint: .red) }
                        Spacer(minLength: 4)
                        if e.relevance == .affected, let sel = selection(e) {
                            Button("Details…") { model.selectedVuln = sel }.buttonStyle(.borderless).font(.system(size: 11.5, weight: .medium))
                        }
                    }
                }
            }
            if g.entries.count == 1, !g.first.summary.isEmpty {
                Text(g.first.summary).font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
            }
            if !g.packages.isEmpty {
                Text((g.relevance == .affected ? "Vulnerable here: " : "Installed here: ") + g.packages.joined(separator: ", "))
                    .font(.system(size: 12.5)).foregroundStyle(g.relevance == .affected ? Color.red : Color.secondary)
            }
            if g.relevance == .installed {
                Text("Heimdall found this product but not a version the advisory data marks as vulnerable. If the listing is new, vendor data may still be catching up — keep it updated.")
                    .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if let fix = g.fix { ModernCommand(text: fix) }
            Link("Open in CISA KEV", destination: URL(string: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=\(g.first.product.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")")!)
                .buttonStyle(.borderless).font(.system(size: 12, weight: .medium))
        }
    }

    func selection(_ entry: TimelineEntry) -> VulnSelection? {
        guard let r = model.visible else { return nil }
        for f in r.findings where entry.packageIDs.contains(f.package.id) {
            if let v = f.vulns.first(where: { $0.cves.contains(entry.cve) }) { return VulnSelection(finding: f, vuln: v) }
        }
        return nil
    }
}

// MARK: - News

/// All the news, newest first; stories about this Mac are highlighted in place.
struct NewsPage: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let all = model.visible?.news
        let q = model.search.lowercased()
        let list = (all ?? []).filter { q.isEmpty || ($0.title + " " + $0.summary + " " + $0.source + " " + $0.cves.joined(separator: " ")).lowercased().contains(q) }
        let days = Dictionary(grouping: list) { Calendar.current.startOfDay(for: $0.published ?? .distantPast) }.sorted { $0.key > $1.key }
        let mine = (all ?? []).filter { $0.relevance != .general }.count

        ModernPageFrame(page: .news) {
            if let all {
                Text("\(all.count) stories · \(mine) about this Mac").font(.system(size: 12)).foregroundStyle(.secondary)
            } else {
                Text("Rescan (⌘R) to fetch the news.").foregroundStyle(.secondary).padding(.top, 24)
            }
            ForEach(days, id: \.key) { d in
                ModernHeading(title: dayTitle(d.key), count: d.value.count, tint: .pink)
                ForEach(d.value) { n in NewsRow(item: n) }
            }
        }
    }

    func dayTitle(_ d: Date) -> String {
        if d == .distantPast { return "Undated" }
        if Calendar.current.isDateInToday(d) { return "Today" }
        if Calendar.current.isDateInYesterday(d) { return "Yesterday" }
        return d.formatted(.dateTime.weekday(.wide).month(.abbreviated).day())
    }
}

struct NewsRow: View {
    @Environment(AppModel.self) private var model
    var item: NewsItem
    var dimmed = false
    @State private var open = false
    @State private var hover = false

    var body: some View {
        let n = item
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Circle().fill(n.relevance == .affected ? Color.red : n.relevance == .installed ? Color.pink : Color.secondary.opacity(0.4))
                    .frame(width: 8, height: 8).frame(width: 16)
                VStack(alignment: .leading, spacing: 3) {
                    Text(n.title).font(.system(size: 13.5, weight: n.relevance == .general ? .regular : .semibold)).lineLimit(open ? nil : 2)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 6) {
                        Text(n.source + (n.published.map { " · " + $0.formatted(date: .omitted, time: .shortened) } ?? ""))
                            .font(.system(size: 12)).foregroundStyle(.secondary)
                        if n.relevance == .affected { ThingsTag(text: "affects you", tint: .red, filled: true) }
                        ForEach(n.mentions.prefix(2), id: \.self) { m in ThingsTag(text: m, tint: n.relevance == .affected ? .red : .pink) }
                        if n.mentions.count > 2 { ThingsTag(text: "+\(n.mentions.count - 2)") }
                        if !n.cves.isEmpty && n.relevance == .general { ThingsTag(text: plural(n.cves.count, "CVE")) }
                    }
                }
                Spacer(minLength: 4)
            }
            .padding(.vertical, 6).padding(.horizontal, 10)
            .background(RoundedRectangle(cornerRadius: 7).fill(hover && !open ? Color.primary.opacity(0.04) : .clear))
            .contentShape(Rectangle())
            .onHover { hover = $0 }
            .onTapGesture { withAnimation(.snappy(duration: 0.22)) { open.toggle() } }

            if open {
                VStack(alignment: .leading, spacing: 8) {
                    if !n.summary.isEmpty { Text(n.summary).font(.system(size: 13)).fixedSize(horizontal: false, vertical: true) }
                    if !n.cves.isEmpty {
                        Text(n.cves.prefix(12).joined(separator: "  ")).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    if !n.mentions.isEmpty {
                        Text((n.relevance == .affected ? "Open here: " : "Installed here: ") + n.mentions.joined(separator: ", "))
                            .font(.system(size: 12.5)).foregroundStyle(n.relevance == .affected ? Color.red : Color.secondary)
                    }
                    HStack(spacing: 14) {
                        if let u = URL(string: n.link), u.scheme == "https" || u.scheme == "http" {
                            Button("Read at \(n.source)") { NSWorkspace.shared.open(u) }
                            Button("Copy Link") { model.copy(n.link) }
                        }
                    }
                    .buttonStyle(.borderless).font(.system(size: 12, weight: .medium))
                }
                .padding(.leading, 36).padding(.trailing, 10).padding(.bottom, 12).padding(.top, 2)
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
        .opacity(dimmed ? 0.65 : 1)
    }
}

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
                if g.topSeverity != .unknown { ThingsTag(text: g.topSeverity.title.lowercased(), tint: g.topSeverity.tint) }
                if g.vulns.contains(where: \.hasPublicExploit) { ThingsTag(text: "public exploit", tint: .purple) }
                if waiting { ThingsTag(text: first?.brewFormula != nil ? "no fixed build yet" : "no fix released yet") }
                else if first?.outdated == true, let f = first?.brewFormula { ThingsTag(text: "brew upgrade \(f)", tint: .blue) }
                Text(g.vulns.count.formatted()).font(.system(size: 12)).foregroundStyle(.secondary).frame(minWidth: 22, alignment: .trailing)
            }
            .padding(.vertical, 6).padding(.horizontal, 10)
            .background(RoundedRectangle(cornerRadius: 7).fill(hover && !open ? Color.primary.opacity(0.04) : .clear))
            .contentShape(Rectangle())
            .onHover { hover = $0 }
            .onTapGesture { withAnimation(.snappy(duration: 0.22)) { open.toggle() } }

            if open {
                VStack(alignment: .leading, spacing: 6) {
                    ModernCommand(text: g.findings.first?.fixHint ?? "")
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(g.findings) { f in ModernFindingRow(finding: f) }
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
