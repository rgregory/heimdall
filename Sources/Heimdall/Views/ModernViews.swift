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
                    sidebarRow(.stats, nil)
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
                    case .stats: StatsPage()
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
                    Button("Report as JSON…") { model.export(.json) }
                    Button("Advisories as CSV…") { model.export(.csv) }
                    Button("SBOM as CycloneDX…") { model.export(.cycloneDX) }
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
            Text(model.scanning ? "Looking around…" : (model.loaded ? "No scan yet" : "Reading the last report…")).font(.title2.bold())
            Text(model.scanning ? model.stage : "Heimdall reads only what your account can read.").foregroundStyle(.secondary)
            if model.scanning { ProgressView(value: model.progress).frame(width: 240) }
            else if model.loaded { Button("Scan Now") { model.scan() }.controlSize(.large).buttonStyle(.borderedProminent) }
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
