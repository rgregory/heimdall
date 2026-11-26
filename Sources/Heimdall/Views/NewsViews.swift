import AppKit
import HeimdallCore
import SwiftUI

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
