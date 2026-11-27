import AppKit
import Charts
import HeimdallCore
import SwiftUI

// MARK: - News

/// The news as a triage list: what touches this Mac first, then what's exploited, advisories,
/// campaigns, and a closed drawer of digests. The telemetry cards and the 30-day matrix on top
/// filter the list; Esc or Clear resets it.
struct NewsPage: View {
    @Environment(AppModel.self) private var model
    @State private var filter: NewsFilter = .none
    /// Sections the user opened that start closed, and closed that start open.
    @State private var opened: Set<NewsSection> = []
    @State private var closed: Set<NewsSection> = []
    /// Domain sub-groups the user folded ("2-9" = Advisories › Data Center).
    @State private var foldedDomains: Set<String> = []
    @AppStorage("newsMatrixShown") private var matrixShown = true

    var body: some View {
        ModernPageFrame(page: .news) {
            if let a = model.newsAnalysis {
                let groups = a.sections(filter: filter, search: model.search)
                NewsTelemetryStrip(analysis: a, filter: $filter)
                NewsActivityMatrix(analysis: a, filter: $filter, shown: $matrixShown).padding(.top, 12)
                if filter != .none {
                    NewsFilterBar(text: describe(filter, a), count: groups.reduce(0) { $0 + $1.storyCount }) { set(.none) }
                        .padding(.top, 12)
                }
                ForEach(groups) { g in section(g) }
            } else {
                Text("Rescan (⌘R) to fetch the news.").foregroundStyle(.secondary).padding(.top, 24)
            }
        }
    }

    @ViewBuilder func section(_ g: NewsSectionGroup) -> some View {
        let sec = g.section
        if g.units.isEmpty {
            // "Nothing here" is news too, but only for this Mac and only when unfiltered.
            if sec == .onThisMac && filter == .none {
                NewsSectionHeader(section: sec, count: 0, collapsible: false, collapsed: false) {}
                Label("No stories in the last 30 days name software installed here.", systemImage: "checkmark.shield")
                    .font(.system(size: 12.5)).foregroundStyle(.secondary)
                    .padding(.horizontal, 10).padding(.vertical, 6)
            }
        } else {
            let shut = isCollapsed(sec)
            NewsSectionHeader(section: sec, count: g.storyCount, collapsible: filter == .none, collapsed: shut) { toggle(sec) }
            if !shut {
                if g.groupsByDomain {
                    ForEach(g.byDomain) { d in
                        let folded = filter == .none && foldedDomains.contains(d.id)
                        NewsDomainHeader(group: d, folded: folded, tint: newsTint(sec)) {
                            withAnimation(.snappy(duration: 0.2)) { foldedDomains.formSymmetricDifference([d.id]) }
                        }
                        if !folded { units(d.units) }
                    }
                } else {
                    units(g.units)
                }
            }
        }
    }

    @ViewBuilder func units(_ list: [NewsUnit]) -> some View {
        ForEach(list) { u in
            if u.isCluster { NewsClusterCard(unit: u) }
            else { NewsRow(story: u.lead, recurrence: u.recurrence) }
        }
    }

    /// A filter opens every section, so nothing that matches hides in a closed drawer.
    func isCollapsed(_ s: NewsSection) -> Bool {
        if filter != .none { return false }
        return s.collapsedByDefault ? !opened.contains(s) : closed.contains(s)
    }

    func toggle(_ s: NewsSection) {
        withAnimation(.snappy(duration: 0.22)) {
            if s.collapsedByDefault { opened.formSymmetricDifference([s]) } else { closed.formSymmetricDifference([s]) }
        }
    }

    func set(_ f: NewsFilter) { withAnimation(.snappy(duration: 0.2)) { filter = f } }

    func describe(_ f: NewsFilter, _ a: NewsAnalysis) -> String {
        func day(_ d: Int) -> String { a.days.indices.contains(d) ? newsDayTitle(a.days[d]) : "?" }
        switch f {
        case .none: return ""
        case .onThisMac: return "About this Mac"
        case .exploited: return "Exploited"
        case .lane(let l): return l.title
        case .day(let d): return day(d)
        case .cell(let d, let l): return "\(l.title) · \(day(d))"
        }
    }
}

// MARK: - Shared bits

func newsDayTitle(_ d: Date) -> String {
    if Calendar.current.isDateInToday(d) { return "Today" }
    if Calendar.current.isDateInYesterday(d) { return "Yesterday" }
    return d.formatted(.dateTime.weekday(.abbreviated).month(.abbreviated).day())
}

/// "2:02 AM" today, "Nov 21" before that.
func newsWhen(_ d: Date?) -> String {
    guard let d else { return "Undated" }
    return Calendar.current.isDateInToday(d) ? d.formatted(date: .omitted, time: .shortened) : d.formatted(.dateTime.month(.abbreviated).day())
}

func newsTint(_ s: NewsSection) -> Color {
    switch s {
    case .onThisMac: return .pink
    case .exploited: return .red
    case .advisories: return .blue
    case .campaigns: return .orange
    case .digest: return .secondary
    }
}

func newsTierLabel(_ t: NewsTier) -> String {
    switch t {
    case .affected: return "Affects this Mac"
    case .installed: return "Names software installed here"
    case .exploited: return "Exploited"
    case .advisory: return "Advisory"
    case .campaign: return "Campaign or malware"
    case .digest: return "Digest or other"
    }
}

/// One shape per tier, so the list reads without colour: filled circle with a halo (open CVE
/// here), filled circle (installed), filled diamond (exploited), square outline (advisory),
/// ring (campaign), small dot (digest).
struct NewsTierMark: View {
    var tier: NewsTier
    var body: some View {
        Group {
            switch tier {
            case .affected:
                ZStack {
                    Circle().fill(Color.red.opacity(0.22)).frame(width: 13, height: 13)
                    Circle().fill(Color.red).frame(width: 7, height: 7)
                }
            case .installed:
                Circle().fill(Color.pink).frame(width: 7, height: 7)
            case .exploited:
                RoundedRectangle(cornerRadius: 1.5).fill(Color.red).frame(width: 6.5, height: 6.5).rotationEffect(.degrees(45))
            case .advisory:
                RoundedRectangle(cornerRadius: 1.5).strokeBorder(Color.blue, lineWidth: 1.5).frame(width: 7.5, height: 7.5)
            case .campaign:
                Circle().strokeBorder(Color.orange, lineWidth: 1.5).frame(width: 8, height: 8)
            case .digest:
                Circle().fill(Color.secondary.opacity(0.5)).frame(width: 5, height: 5)
            }
        }
        .frame(width: 16, height: 16)
        .accessibilityLabel(newsTierLabel(tier))
    }
}

struct NewsSectionHeader: View {
    var section: NewsSection
    var count: Int
    var collapsible: Bool
    var collapsed: Bool
    var toggle: () -> Void

    var body: some View {
        Group {
            if collapsible {
                Button(action: toggle) { label }.buttonStyle(.plain)
            } else {
                label
            }
        }
        .padding(.top, 22).padding(.bottom, 4)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(section.title), \(plural(count, "story", "stories"))" + (collapsible ? (collapsed ? ", collapsed" : ", expanded") : ""))
        .accessibilityAddTraits(collapsible ? .isButton : [])
    }

    var label: some View {
        let tint = newsTint(section)
        return VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                if collapsible {
                    Image(systemName: "chevron.right").font(.system(size: 9, weight: .bold))
                        .rotationEffect(.degrees(collapsed ? 0 : 90)).foregroundStyle(tint.opacity(0.8))
                }
                Text(section.title).font(.system(size: 13.5, weight: .semibold)).foregroundStyle(tint)
                Spacer()
                Text(count.formatted()).font(.system(size: 12)).foregroundStyle(.secondary)
            }
            Rectangle().fill(tint.opacity(0.25)).frame(height: 1)
        }
        .contentShape(Rectangle())
    }
}

/// A quiet sub-heading inside a section: what kind of system these stories are about. Domains a
/// Mac user runs (Apple, desktop apps, developer tools…) carry the section's colour; servers and
/// appliances someone else runs stay grey.
struct NewsDomainHeader: View {
    var group: NewsDomainGroup
    var folded: Bool
    var tint: Color
    var toggle: () -> Void

    var body: some View {
        let near = group.domain.nearThisMac
        Button(action: toggle) {
            HStack(spacing: 6) {
                Image(systemName: newsDomainSymbol(group.domain))
                    .font(.system(size: 10.5, weight: .semibold))
                    .foregroundStyle(near ? tint : Color.secondary)
                    .frame(width: 16)
                Text(group.domain.title)
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundStyle(near ? Color.primary.opacity(0.8) : Color.secondary)
                Text(group.storyCount.formatted())
                    .font(.system(size: 11)).foregroundStyle(.tertiary)
                Image(systemName: "chevron.right").font(.system(size: 8, weight: .bold)).foregroundStyle(.tertiary)
                    .rotationEffect(.degrees(folded ? 0 : 90))
                Spacer()
            }
            .padding(.horizontal, 10).padding(.top, 12).padding(.bottom, 3)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(near ? "Software people run on Macs and laptops" : "Servers and devices someone else usually runs")
        .accessibilityLabel("\(group.domain.title), \(plural(group.storyCount, "story", "stories")), \(folded ? "collapsed" : "expanded")")
    }
}

func newsDomainSymbol(_ d: NewsDomain) -> String {
    switch d {
    case .apple: return "apple.logo"
    case .desktop: return "macwindow"
    case .developer: return "shippingbox"
    case .ai: return "sparkles"
    case .cloud: return "cloud"
    case .mobile: return "iphone"
    case .remote: return "display.2"
    case .web: return "globe"
    case .network: return "network"
    case .datacenter: return "server.rack"
    case .industrial: return "gearshape.2"
    case .general: return "circle.grid.2x2"
    }
}

struct NewsFilterBar: View {
    var text: String
    var count: Int
    var clear: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "line.3.horizontal.decrease.circle.fill").foregroundStyle(Color.accentColor)
            (Text("Showing: ").foregroundColor(.secondary) + Text(text).fontWeight(.semibold)
                + Text("  \(plural(count, "story", "stories"))").foregroundColor(.secondary))
            Spacer()
            Button("Clear", action: clear).keyboardShortcut(.cancelAction).controlSize(.small).help("Show everything (Esc)")
        }
        .font(.system(size: 12))
        .padding(.horizontal, 10).padding(.vertical, 7)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.accentColor.opacity(0.08)))
    }
}

// MARK: - Telemetry

struct NewsTelemetryStrip: View {
    var analysis: NewsAnalysis
    @Binding var filter: NewsFilter

    var body: some View {
        HStack(spacing: 12) {
            ForEach(analysis.metrics) { m in
                let target = Self.target(m.kind)
                NewsMetricCard(metric: m, tint: Self.tint(m.kind), selected: target != .none && filter == target) {
                    withAnimation(.snappy(duration: 0.2)) { filter = (target == .none || filter == target) ? .none : target }
                }
            }
        }
    }

    /// The volume card has nothing to narrow to: clicking it shows everything.
    static func target(_ k: NewsMetric.Kind) -> NewsFilter {
        switch k {
        case .onThisMac: return .onThisMac
        case .exploited: return .exploited
        case .volume: return .none
        }
    }
    static func tint(_ k: NewsMetric.Kind) -> Color {
        switch k {
        case .onThisMac: return .pink
        case .exploited: return .red
        case .volume: return .secondary
        }
    }
}

struct NewsMetricCard: View {
    var metric: NewsMetric
    var tint: Color
    var selected: Bool
    var action: () -> Void
    @State private var hover = false

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 10)
        Button(action: action) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 6) {
                    Text(metric.title).font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary).lineLimit(1)
                    Spacer(minLength: 4)
                    trendPill
                }
                HStack(alignment: .bottom, spacing: 8) {
                    Text(metric.total.formatted()).font(.system(size: 20, weight: .semibold)).monospacedDigit()
                    Spacer(minLength: 4)
                    NewsSparkline(values: metric.buckets, tint: tint).frame(width: 84, height: 24)
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(shape.fill(Color.primary.opacity(hover ? 0.06 : 0.035)))
            .overlay(shape.strokeBorder(selected ? tint : Color.primary.opacity(0.08), lineWidth: selected ? 1.5 : 1))
            .contentShape(shape)
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
        .help(metric.kind == .volume ? "Every story in the last 30 days" : (selected ? "Show everything" : "Show only these stories"))
        .accessibilityLabel("\(metric.title): \(metric.total)" + (metric.trend.text.map { ", \($0) against the week before" } ?? ""))
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    /// Rising is coloured only where rising is bad news; volume going up is just busy.
    @ViewBuilder var trendPill: some View {
        if let t = metric.trend.text {
            let flat = metric.trend == .delta(0) || metric.trend == .percent(0)
            let c: Color = metric.trend.rising && metric.kind != .volume ? tint : .secondary
            HStack(spacing: 2) {
                Image(systemName: metric.trend == .new ? "sparkle" : flat ? "equal" : metric.trend.rising ? "arrow.up.right" : "arrow.down.right")
                    .font(.system(size: 8.5, weight: .bold))
                Text(t).font(.system(size: 10.5, weight: .semibold)).monospacedDigit()
            }
            .foregroundStyle(c)
            .padding(.horizontal, 5).padding(.vertical, 1.5)
            .background(Capsule().fill(c.opacity(0.12)))
            .help("This week against the week before")
        }
    }
}

struct NewsPoint: Identifiable {
    var day: Int
    var value: Int
    var id: Int { day }
}

struct NewsSparkline: View {
    var values: [Int]
    var tint: Color

    var body: some View {
        let points = values.indices.map { NewsPoint(day: $0, value: values[$0]) }
        Chart(points) { p in
            AreaMark(x: .value("Day", p.day), y: .value("Stories", p.value))
                .foregroundStyle(tint.opacity(0.15))
                .interpolationMethod(.monotone)
            LineMark(x: .value("Day", p.day), y: .value("Stories", p.value))
                .foregroundStyle(tint)
                .lineStyle(StrokeStyle(lineWidth: 1.5))
                .interpolationMethod(.monotone)
        }
        .chartXAxis(.hidden)
        .chartYAxis(.hidden)
        .chartLegend(.hidden)
        .chartXScale(domain: 0...max(1, values.count - 1))
        .chartYScale(domain: 0...max(1, values.max() ?? 1))
        .accessibilityHidden(true)
    }
}

// MARK: - Activity matrix

/// Thirty days by desk: when stories came, and which part of this Mac they were about.
/// Filled pink with an outline = names installed software; red with a heavier outline = names an
/// open CVE; a red dot = exploitation reported. Grey depth is volume.
struct NewsActivityMatrix: View {
    var analysis: NewsAnalysis
    @Binding var filter: NewsFilter
    @Binding var shown: Bool

    /// Cells grow with the window up to this size and stay square.
    static let maxCell: CGFloat = 20
    static let gap: CGFloat = 3
    static let labelWidth: CGFloat = 70

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Button { withAnimation(.snappy(duration: 0.2)) { shown.toggle() } } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "chevron.right").font(.system(size: 9, weight: .bold)).rotationEffect(.degrees(shown ? 90 : 0))
                        Text("Last 30 Days").font(.system(size: 12, weight: .semibold))
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain).foregroundStyle(.secondary)
                Spacer()
                if shown { legend }
            }
            if shown {
                VStack(alignment: .leading, spacing: Self.gap) {
                    ForEach(NewsLane.allCases) { lane in row(lane) }
                    axis.padding(.top, 3)
                }
                .transition(.opacity)
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color.primary.opacity(0.035)))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.primary.opacity(0.08)))
    }

    func row(_ lane: NewsLane) -> some View {
        let cells = analysis.matrix[lane] ?? []
        let selected = filter.lane == lane
        return HStack(spacing: Self.gap) {
            Button { select(.lane(lane)) } label: {
                Text(lane.title)
                    .font(.system(size: 11, weight: selected ? .semibold : .regular))
                    .foregroundStyle(selected ? Color.primary : Color.secondary)
                    .frame(width: Self.labelWidth, alignment: .trailing)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .padding(.trailing, 5)
            .help("Show stories about \(lane == .elsewhere ? "software not on this Mac" : lane.title)")
            ForEach(cells) { c in
                NewsMatrixCell(cell: c, dimmed: dimmed(c), selected: filter == .cell(day: c.day, lane: lane))
                    .onTapGesture { select(.cell(day: c.day, lane: lane)) }
                    .help(tooltip(c))
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(summary(lane, cells))
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { select(.lane(lane)) }
    }

    /// A tick per day under the grid: click one to see that whole day.
    var axis: some View {
        HStack(spacing: Self.gap) {
            ForEach(analysis.days.indices, id: \.self) { d in
                RoundedRectangle(cornerRadius: 1)
                    .fill(Color.primary.opacity(filter.day == d ? 0.6 : 0.12))
                    .frame(maxWidth: Self.maxCell).frame(height: 4)
                    .contentShape(Rectangle().inset(by: -3))
                    .onTapGesture { select(.day(d)) }
                    .help("Show everything from \(newsDayTitle(analysis.days[d]))")
            }
        }
        .padding(.bottom, 16)
        // Labels ride on the tick row so they span exactly the grid, whatever its width.
        .overlay(alignment: .bottom) {
            HStack {
                Text("30d ago")
                Spacer()
                Text("15d ago")
                Spacer()
                Text("Today")
            }
            .font(.system(size: 10)).foregroundStyle(.secondary)
        }
        .padding(.leading, Self.labelWidth + 5 + Self.gap)
        .accessibilityHidden(true)
    }

    var legend: some View {
        HStack(spacing: 4) {
            Text("Less")
            ForEach([0.06, 0.22, 0.45, 0.75], id: \.self) { o in
                RoundedRectangle(cornerRadius: 2).fill(Color.primary.opacity(o)).frame(width: 9, height: 9)
            }
            Text("More").padding(.trailing, 8)
            RoundedRectangle(cornerRadius: 2).fill(Color.pink.opacity(0.55))
                .overlay(RoundedRectangle(cornerRadius: 2).strokeBorder(Color.pink, lineWidth: 1)).frame(width: 9, height: 9)
            Text("Installed").padding(.trailing, 6)
            RoundedRectangle(cornerRadius: 2).fill(Color.red.opacity(0.7))
                .overlay(RoundedRectangle(cornerRadius: 2).strokeBorder(Color.red, lineWidth: 1.5)).frame(width: 9, height: 9)
            Text("Open CVE").padding(.trailing, 6)
            Circle().fill(Color.red).frame(width: 4, height: 4)
            Text("Exploited")
        }
        .font(.system(size: 10)).foregroundStyle(.secondary)
        .accessibilityHidden(true)
    }

    func select(_ f: NewsFilter) {
        withAnimation(.snappy(duration: 0.2)) { filter = filter == f ? .none : f }
    }

    func dimmed(_ c: NewsCell) -> Bool {
        switch filter {
        case .none: return false
        case .onThisMac: return c.local == 0
        case .exploited: return c.exploited == 0
        case .lane(let l): return c.lane != l
        case .day(let d): return c.day != d
        case .cell(let d, let l): return c.day != d || c.lane != l
        }
    }

    func tooltip(_ c: NewsCell) -> String {
        var s = "\(newsDayTitle(c.date)) · \(c.lane.title): \(plural(c.count, "story", "stories"))"
        if c.local > 0 { s += " (\(c.local) about this Mac\(c.affected > 0 ? ", \(c.affected) with an open CVE" : ""))" }
        if c.exploited > 0 { s += " · \(c.exploited) exploited" }
        return s
    }

    func summary(_ lane: NewsLane, _ cells: [NewsCell]) -> String {
        let total = cells.reduce(0) { $0 + $1.count }, local = cells.reduce(0) { $0 + $1.local }
        var s = "\(lane.title): \(plural(total, "story", "stories")) in 30 days"
        if local > 0 { s += ", \(local) about this Mac" }
        if let busiest = cells.max(by: { $0.count < $1.count }), busiest.count > 0 { s += ", most on \(newsDayTitle(busiest.date))" }
        return s
    }
}

struct NewsMatrixCell: View {
    var cell: NewsCell
    var dimmed: Bool
    var selected: Bool

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 2.5)
        shape.fill(fill)
            .overlay {
                if cell.local > 0 { shape.strokeBorder(cell.affected > 0 ? Color.red : Color.pink, lineWidth: cell.affected > 0 ? 1.5 : 1) }
            }
            .overlay {
                if cell.exploited > 0 && cell.local == 0 { Circle().fill(Color.red).frame(width: 4, height: 4) }
            }
            .overlay {
                if selected { RoundedRectangle(cornerRadius: 3.5).strokeBorder(Color.primary, lineWidth: 1.5).padding(-2) }
            }
            .aspectRatio(1, contentMode: .fit)
            .frame(maxWidth: NewsActivityMatrix.maxCell)
            .opacity(dimmed ? 0.3 : 1)
            .contentShape(Rectangle())
    }

    var fill: Color {
        if cell.count == 0 { return Color.primary.opacity(0.06) }
        if cell.affected > 0 { return Color.red.opacity(0.45 + 0.15 * Double(min(cell.affected, 3))) }
        if cell.local > 0 { return Color.pink.opacity(0.35 + 0.15 * Double(min(cell.local, 3))) }
        switch cell.count {
        case 1: return Color.primary.opacity(0.22)
        case 2...3: return Color.primary.opacity(0.45)
        default: return Color.primary.opacity(0.75)
        }
    }
}

// MARK: - Clusters

/// Several stories about one CVE, actor or product within a week, as one card that opens into a
/// timeline.
struct NewsClusterCard: View {
    var unit: NewsUnit
    @State private var open = false
    @State private var hover = false

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 10)
        VStack(alignment: .leading, spacing: 0) {
            Button { withAnimation(.snappy(duration: 0.22)) { open.toggle() } } label: { header }
                .buttonStyle(.plain)
                .onHover { hover = $0 }
            if open {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(unit.stories) { s in
                        HStack(alignment: .top, spacing: 0) {
                            Rectangle().fill(Color.secondary.opacity(0.3)).frame(width: 1).frame(maxHeight: .infinity)
                                .padding(.leading, 17.5).padding(.trailing, 4)
                            NewsRow(story: s, inCluster: true)
                        }
                        .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(.bottom, 6)
                .transition(.opacity)
            }
        }
        .background(shape.fill(Color.primary.opacity(hover && !open ? 0.05 : 0.03)))
        .overlay(shape.strokeBorder(Color.primary.opacity(0.07)))
        .padding(.vertical, 3)
    }

    var header: some View {
        let lead = unit.lead
        let strong = unit.tier <= .exploited
        return HStack(alignment: .top, spacing: 10) {
            NewsTierMark(tier: unit.tier).padding(.top, 1)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    NewsStageBadge(stage: unit.stage)
                    if unit.tier == .affected { ThingsTag(text: "affects you", tint: .red, filled: true) }
                    if let k = unit.key { ThingsTag(text: k.label) }
                    if unit.fix { ThingsTag(text: "fix out", tint: .green) }
                    if let r = unit.recurrence { ThingsTag(text: r.text, tint: .orange).help(recurrenceHelp(r)) }
                    NewsVelocityBars(values: unit.velocity, tint: stageTint(unit.stage))
                    Spacer(minLength: 4)
                    HStack(spacing: 3) {
                        Text(countText)
                        Image(systemName: "chevron.right").font(.system(size: 8.5, weight: .bold)).rotationEffect(.degrees(open ? 90 : 0))
                    }
                    .font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
                }
                Text(lead.item.title).font(.system(size: 13.5, weight: strong ? .semibold : .regular)).lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                Text(sourcesLine).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
            }
        }
        .padding(.vertical, 8).padding(.horizontal, 10)
        .contentShape(Rectangle())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(newsTierLabel(unit.tier)), \(unit.stage.title.lowercased()), \(countText): \(lead.item.title)")
        .accessibilityHint(open ? "Collapses the timeline" : "Shows every story")
    }

    var countText: String {
        unit.stories.count == unit.total ? "\(unit.total) stories" : "\(unit.stories.count) of \(unit.total) stories"
    }

    var sourcesLine: String {
        let names = unit.stories.map(\.item.source).uniqued()
        let shown = names.prefix(2).joined(separator: ", ") + (names.count > 2 ? " +\(names.count - 2)" : "")
        return shown + " · latest " + newsWhen(unit.latest)
    }
}

func stageTint(_ s: NewsStage) -> Color {
    switch s {
    case .exploited: return .red
    case .escalating: return .orange
    case .new: return .blue
    case .ongoing: return .secondary
    }
}

func recurrenceHelp(_ r: NewsRecurrence) -> String {
    "\(r.key.label) has been in the news on \(r.ordinal) separate days in the last 30"
}

struct NewsStageBadge: View {
    var stage: NewsStage
    var body: some View {
        let tint = stageTint(stage)
        HStack(spacing: 3) {
            Image(systemName: symbol).font(.system(size: 8.5, weight: .bold))
            Text(stage.title).font(.system(size: 10, weight: .bold)).tracking(0.4)
        }
        .foregroundStyle(tint)
        .padding(.horizontal, 6).padding(.vertical, 2)
        .background(RoundedRectangle(cornerRadius: 4).fill(tint.opacity(0.14)))
        .fixedSize()
    }
    var symbol: String {
        switch stage {
        case .exploited: return "flame.fill"
        case .escalating: return "arrow.up.right"
        case .new: return "sparkle"
        case .ongoing: return "clock"
        }
    }
}

/// Stories per day over the cluster's last seven days.
struct NewsVelocityBars: View {
    var values: [Int]
    var tint: Color
    var body: some View {
        let top = CGFloat(max(1, values.max() ?? 1))
        HStack(alignment: .bottom, spacing: 1.5) {
            ForEach(values.indices, id: \.self) { i in
                let v = CGFloat(values[i])
                RoundedRectangle(cornerRadius: 1)
                    .fill(v > 0 ? tint.opacity(0.85) : Color.primary.opacity(0.12))
                    .frame(width: 3, height: v > 0 ? max(3, 12 * v / top) : 2)
            }
        }
        .frame(height: 12, alignment: .bottom)
        .help("Stories per day, last 7 days of this story")
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Stories per day over seven days: " + values.map(String.init).joined(separator: ", "))
    }
}

// MARK: - Row

struct NewsRow: View {
    @Environment(AppModel.self) private var model
    var item: NewsItem
    var tier: NewsTier
    var fix = false
    var recurrence: NewsRecurrence? = nil
    /// Inside a cluster's timeline: the cluster already shows tier, fix and recurrence.
    var inCluster = false
    var dimmed = false
    @State private var open = false
    @State private var hover = false

    init(story: NewsStory, recurrence: NewsRecurrence? = nil, inCluster: Bool = false) {
        item = story.item; tier = story.tier; fix = story.fix; self.recurrence = recurrence; self.inCluster = inCluster
    }

    /// For the Brief, which shows raw items without the analysis.
    init(item: NewsItem, dimmed: Bool = false) {
        self.item = item; self.dimmed = dimmed
        switch item.relevance {
        case .affected: tier = .affected
        case .installed: tier = .installed
        case .general: tier = item.cves.isEmpty ? .digest : .advisory
        }
    }

    var body: some View {
        let n = item
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                if inCluster {
                    Circle().fill(Color.secondary.opacity(0.6)).frame(width: 5, height: 5).frame(width: 10)
                } else {
                    NewsTierMark(tier: tier)
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text(n.title)
                        .font(.system(size: inCluster ? 13 : 13.5, weight: !inCluster && tier <= .exploited ? .semibold : .regular))
                        .lineLimit(open ? nil : 2)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 6) {
                        Text(n.source + " · " + newsWhen(n.published)).font(.system(size: 12)).foregroundStyle(.secondary)
                        if !inCluster && tier == .affected { ThingsTag(text: "affects you", tint: .red, filled: true) }
                        ForEach(n.mentions.prefix(2), id: \.self) { m in
                            ThingsTag(text: m, tint: tier == .affected ? .red : tier == .installed ? .pink : .secondary)
                                .help(tier <= .installed ? "Installed on this Mac" : "Installed here, but only mentioned in passing")
                        }
                        if n.mentions.count > 2 { ThingsTag(text: "+\(n.mentions.count - 2)") }
                        if !n.cves.isEmpty && n.relevance == .general { ThingsTag(text: plural(n.cves.count, "CVE")) }
                        if !inCluster && fix && tier <= .advisory { ThingsTag(text: "fix out", tint: .green) }
                        if let r = recurrence, !inCluster { ThingsTag(text: r.text, tint: .orange).help(recurrenceHelp(r)) }
                    }
                }
                Spacer(minLength: 4)
            }
            .padding(.vertical, 6).padding(.horizontal, 10)
            .background(RoundedRectangle(cornerRadius: 7).fill(hover && !open ? Color.primary.opacity(0.04) : .clear))
            .contentShape(Rectangle())
            .onHover { hover = $0 }
            .onTapGesture { withAnimation(.snappy(duration: 0.22)) { open.toggle() } }
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(.isButton)

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
                .padding(.leading, inCluster ? 30 : 36).padding(.trailing, 10).padding(.bottom, 12).padding(.top, 2)
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
