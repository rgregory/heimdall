import Charts
import HeimdallCore
import SwiftUI

// MARK: - Filter

/// What the band above the table is currently narrowing the table to. Every control in the
/// band is a toggle: click it once to narrow, again to go back to everything.
struct LedgerFilter: Equatable {
    var severities: Set<Severity> = []
    var exploited = false
    var reachable = false
    var fixable = false
    /// One thing you would actually update: the binary or app that carries the advisories.
    var carrier: String?
    /// Stacking conditions reads as "and" — exploited AND running AND fixable — which on a
    /// healthy Mac is correctly empty and looks broken. "Any" asks the other question:
    /// everything that is at least one of these. Both are useful; neither is the only answer.
    var matchAll = true

    var active: Bool { !severities.isEmpty || exploited || reachable || fixable || carrier != nil }
    /// How many conditions are switched on, which is what decides whether and/or matters.
    var conditions: Int {
        (severities.isEmpty ? 0 : 1) + (exploited ? 1 : 0) + (reachable ? 1 : 0) + (fixable ? 1 : 0) + (carrier == nil ? 0 : 1)
    }

    func matches(_ r: LedgerRow) -> Bool {
        guard active else { return true }
        // A carrier is a scope rather than a condition: picking one from the map means
        // "inside this package", so it holds in either mode.
        if let carrier, r.carrier != carrier { return false }
        var tests: [Bool] = []
        if !severities.isEmpty { tests.append(severities.contains(r.vuln.severity)) }
        if exploited { tests.append(r.vuln.isKEV) }
        if reachable { tests.append(r.reachable) }
        if fixable { tests.append(r.fixable) }
        if tests.isEmpty { return true }
        return matchAll ? tests.allSatisfy { $0 } : tests.contains(true)
    }

    mutating func toggle(_ s: Severity) {
        if severities.contains(s) { severities.remove(s) } else { severities.insert(s) }
    }

    var summary: String {
        var parts: [String] = []
        if !severities.isEmpty {
            parts.append(Severity.allCases.filter { severities.contains($0) }.map { $0.title.lowercased() }.joined(separator: " or "))
        }
        if exploited { parts.append("exploited") }
        if reachable { parts.append("running here") }
        if fixable { parts.append("fixable now") }
        // The joiner is the setting, written out, so the table never disagrees with the label.
        let conditions = parts.joined(separator: matchAll ? " and " : " or ")
        if let carrier { return conditions.isEmpty ? carrier : "\(carrier): \(conditions)" }
        return conditions
    }
}

// MARK: - The band

/// Two pictures over the ledger: how the count has moved, and how much of it actually matters.
/// Everything in here filters the table underneath, so the charts are the controls.
/// The ways of looking at the same advisories. Each one is better at a different shape of
/// data, so the choice stays with whoever is reading it.
enum LedgerView: String, CaseIterable, Identifiable {
    case bars, dots, map, table
    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .bars: return "chart.bar.xaxis"
        case .dots: return "circle.grid.3x3.fill"
        case .map: return "square.grid.2x2"
        case .table: return "list.bullet"
        }
    }
    var help: String {
        switch self {
        case .bars: return "Ranked bars — readable however lopsided the counts are"
        case .dots: return "One square per advisory"
        case .map: return "Area is the count — best when the load is spread"
        case .table: return "Every advisory, one line each"
        }
    }
}

struct AdvisoryInsights: View {
    @Environment(AppModel.self) private var model
    var rows: [LedgerRow]
    @Binding var filter: LedgerFilter
    @Binding var view: LedgerView
    @AppStorage("ledgerCharts") private var expanded = true

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Text("Trend and Impact").font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Page.ledger.tint)
                Spacer()
                if filter.conditions > 1 {
                    Picker("", selection: $filter.matchAll) {
                        Text("All").tag(true)
                        Text("Any").tag(false)
                    }
                    .pickerStyle(.segmented).labelsHidden().fixedSize().controlSize(.small)
                    .help(filter.matchAll ? "Rows meeting every condition" : "Rows meeting at least one condition")
                }
                Picker("", selection: $view) {
                    ForEach(LedgerView.allCases) { v in Image(systemName: v.symbol).tag(v) }
                }
                .pickerStyle(.segmented).labelsHidden().fixedSize().controlSize(.small)
                .help(view.help)
                if filter.active {
                    Button {
                        withAnimation(.snappy(duration: 0.2)) { filter = LedgerFilter() }
                    } label: {
                        Label("Showing \(filter.summary)", systemImage: "xmark.circle.fill")
                    }
                    .buttonStyle(.borderless).font(.system(size: 11.5, weight: .medium)).foregroundStyle(.secondary)
                }
                Button(expanded ? "Hide" : "Show") { withAnimation(.snappy(duration: 0.22)) { expanded.toggle() } }
                    .buttonStyle(.borderless).font(.system(size: 11.5, weight: .medium))
            }
            if expanded {
                HStack(alignment: .top, spacing: 12) {
                    Panel(title: "Open advisories over time", tint: .teal) {
                        TrendChart(scans: model.trend)
                    }
                    .frame(maxWidth: .infinity)
                    Panel(title: "", tint: .red) {
                        ImpactLadder(rows: rows, filter: $filter)
                    }
                    .frame(width: 344)
                }
                .frame(height: 148)
                SeverityStrip(rows: rows, filter: $filter)
            }
        }
        .padding(.horizontal, 28).padding(.bottom, 12)
    }
}

/// A quiet card: hairline, label, content. Matches the cards a row opens into.
struct Panel<Content: View>: View {
    var title: String
    var tint: Color
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if !title.isEmpty {
                HStack(spacing: 5) {
                    Circle().fill(tint.opacity(0.75)).frame(width: 6, height: 6)
                    Text(title).font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
                }
            }
            content
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(nsColor: .textBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.primary.opacity(0.07)))
    }
}

// MARK: - Trend

/// Advisory count per scan, with the exploited ones filled underneath it. The history file
/// keeps a year of scans, so this is the only place that can say whether things are getting
/// better or whether the same flaws keep piling up.
struct TrendChart: View {
    var scans: [History.Scan]
    @State private var hovered: History.Scan?

    var recent: [History.Scan] {
        let cutoff = Date().addingTimeInterval(-90 * 86400)
        let window = scans.filter { $0.date >= cutoff }
        return window.count >= 2 ? window : Array(scans.suffix(2))
    }

    var body: some View {
        let list = recent
        if list.count < 2 {
            VStack(alignment: .leading, spacing: 3) {
                Text("The trend starts at the second scan.").font(.system(size: 12.5))
                Text("Heimdall keeps one row per scan, up to a year of them.").font(.system(size: 11.5)).foregroundStyle(.secondary)
            }
            .frame(maxHeight: .infinity, alignment: .center)
        } else {
            let now = list.last!
            let shown = hovered ?? now
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(shown.findings.formatted()).font(.system(size: 22, weight: .semibold)).monospacedDigit()
                    Text(hovered == nil ? "open" : "on \(shown.date.formatted(.dateTime.month(.abbreviated).day()))")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                    if shown.exploited > 0 {
                        ThingsTag(text: "\(shown.exploited) exploited", tint: .red, filled: true)
                    }
                    Spacer(minLength: 4)
                    if hovered == nil, let caption = caption { Text(caption).font(.system(size: 11.5)).foregroundStyle(.secondary) }
                }
                chart(list)
            }
        }
    }

    /// "4 more than a week ago" — the comparison a glance is actually asking for.
    var caption: String? {
        guard let now = recent.last else { return nil }
        let weekAgo = recent.last { $0.date <= now.date.addingTimeInterval(-7 * 86400) } ?? recent.first
        guard let then = weekAgo, then.date != now.date else { return nil }
        let d = now.findings - then.findings
        let days = max(1, Int(now.date.timeIntervalSince(then.date) / 86400))
        let span = days >= 60 ? "\(days / 30) months ago" : days >= 12 ? "\(days) days ago" : days >= 5 ? "a week ago" : "\(plural(days, "day")) ago"
        if d == 0 { return "level with \(span)" }
        return "\(d > 0 ? "+" : "")\(d) since \(span)"
    }

    func chart(_ list: [History.Scan]) -> some View {
        Chart {
            ForEach(list) { s in
                AreaMark(x: .value("Day", s.date), y: .value("Advisories", s.findings), stacking: .unstacked)
                    .interpolationMethod(.monotone)
                    .foregroundStyle(.linearGradient(colors: [Color.teal.opacity(0.28), Color.teal.opacity(0.03)], startPoint: .top, endPoint: .bottom))
                LineMark(x: .value("Day", s.date), y: .value("Advisories", s.findings), series: .value("Series", "open"))
                    .interpolationMethod(.monotone)
                    .foregroundStyle(Color.teal)
                    .lineStyle(StrokeStyle(lineWidth: 1.8))
            }
            ForEach(list) { s in
                AreaMark(x: .value("Day", s.date), y: .value("Exploited", s.exploited), stacking: .unstacked)
                    .interpolationMethod(.monotone)
                    .foregroundStyle(.linearGradient(colors: [Color.red.opacity(0.45), Color.red.opacity(0.1)], startPoint: .top, endPoint: .bottom))
                LineMark(x: .value("Day", s.date), y: .value("Exploited", s.exploited), series: .value("Series", "exploited"))
                    .interpolationMethod(.monotone)
                    .foregroundStyle(Color.red)
                    .lineStyle(StrokeStyle(lineWidth: 1.4))
            }
            if let h = hovered {
                RuleMark(x: .value("Day", h.date))
                    .foregroundStyle(Color.primary.opacity(0.18))
                    .lineStyle(StrokeStyle(lineWidth: 1, dash: [3, 3]))
                PointMark(x: .value("Day", h.date), y: .value("Advisories", h.findings))
                    .foregroundStyle(Color.teal).symbolSize(42)
            }
        }
        .chartYAxis {
            AxisMarks(position: .trailing, values: .automatic(desiredCount: 3)) {
                AxisGridLine().foregroundStyle(Color.primary.opacity(0.07))
                AxisValueLabel().font(.system(size: 9)).foregroundStyle(.secondary)
            }
        }
        .chartXAxis {
            AxisMarks(values: .automatic(desiredCount: 4)) {
                AxisValueLabel(format: .dateTime.month(.abbreviated).day()).font(.system(size: 9)).foregroundStyle(.secondary)
            }
        }
        .chartOverlay { proxy in
            GeometryReader { geo in
                Rectangle().fill(.clear).contentShape(Rectangle())
                    .onContinuousHover { phase in
                        guard let plot = proxy.plotFrame else { return }
                        switch phase {
                        case .active(let pt):
                            let x = pt.x - geo[plot].origin.x
                            guard let date: Date = proxy.value(atX: x) else { hovered = nil; return }
                            hovered = list.min { abs($0.date.timeIntervalSince(date)) < abs($1.date.timeIntervalSince(date)) }
                        case .ended:
                            hovered = nil
                        }
                    }
            }
        }
    }
}

// MARK: - Impact

/// The table has every advisory in it, which is not the same as every advisory being work.
/// Each step narrows by one honest question, and clicking a step narrows the table the same way.
struct ImpactLadder: View {
    var rows: [LedgerRow]
    @Binding var filter: LedgerFilter

    struct Step: Identifiable {
        var label: String, count: Int, tint: Color, apply: (inout LedgerFilter) -> Void, on: (LedgerFilter) -> Bool
        var id: String { label }
    }

    var steps: [Step] {
        let severe: Set<Severity> = [.critical, .high]
        return [
            Step(label: "All advisories", count: rows.count, tint: .secondary,
                 apply: { $0 = LedgerFilter() }, on: { !$0.active }),
            Step(label: "High or critical", count: rows.filter { severe.contains($0.vuln.severity) }.count, tint: .orange,
                 apply: { $0.severities = $0.severities == severe ? [] : severe }, on: { $0.severities == severe }),
            Step(label: "Exploited in the wild", count: rows.filter { $0.vuln.isKEV }.count, tint: .red,
                 apply: { $0.exploited.toggle() }, on: { $0.exploited }),
            Step(label: "Running or listening", count: rows.filter { $0.reachable }.count, tint: .purple,
                 apply: { $0.reachable.toggle() }, on: { $0.reachable }),
            Step(label: "Fixable tonight", count: rows.filter { $0.fixable }.count, tint: .blue,
                 apply: { $0.fixable.toggle() }, on: { $0.fixable }),
        ]
    }

    /// Share of every advisory in the ledger. One in three hundred is not nothing, so it
    /// rounds to "<1%" rather than to zero.
    func share(_ n: Int) -> String {
        guard n > 0 else { return "0%" }
        let pct = Double(n) / Double(max(1, rows.count)) * 100
        return pct < 1 ? "<1%" : "\(Int(pct.rounded()))%"
    }

    var body: some View {
        let all = max(1, rows.count)
        VStack(alignment: .leading, spacing: 9) {
            ForEach(steps) { s in
                let on = s.on(filter)
                Button {
                    withAnimation(.snappy(duration: 0.2)) { var f = filter; s.apply(&f); filter = f }
                } label: {
                    HStack(spacing: 8) {
                        Text(s.label).font(.system(size: 11.5, weight: on ? .semibold : .regular))
                            .foregroundStyle(on ? Color.primary : .secondary)
                            .frame(width: 118, alignment: .leading).lineLimit(1)
                        GeometryReader { geo in
                            ZStack(alignment: .leading) {
                                Capsule().fill(Color.primary.opacity(0.05))
                                Capsule().fill(s.tint.opacity(on ? 0.95 : 0.55))
                                    .frame(width: max(s.count == 0 ? 0 : 4, geo.size.width * CGFloat(s.count) / CGFloat(all)))
                            }
                        }
                        .frame(height: 9)
                        // The count says how many; the share says whether that is a lot.
                        HStack(spacing: 4) {
                            Text(s.count.formatted()).font(.system(size: 11.5, weight: .medium)).monospacedDigit()
                                .foregroundStyle(s.count == 0 ? AnyShapeStyle(.tertiary) : (on ? AnyShapeStyle(s.tint) : AnyShapeStyle(Color.primary)))
                            Text(share(s.count))
                                .font(.system(size: 10.5).monospacedDigit()).foregroundStyle(.tertiary)
                                .frame(width: 30, alignment: .trailing)
                        }
                        .frame(width: 62, alignment: .trailing)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help(s.count == 0 ? "Nothing here" : "Show only these")
            }
        }
        .frame(maxHeight: .infinity, alignment: .center)
    }
}

// MARK: - Severity strip

/// One bar for the whole ledger, split by severity, with the counts beside it as toggles.
struct SeverityStrip: View {
    var rows: [LedgerRow]
    @Binding var filter: LedgerFilter

    struct Slice: Identifiable {
        var severity: Severity
        var count: Int
        var id: Severity { severity }
    }

    var slices: [Slice] {
        [Severity.critical, .high, .medium, .low, .none, .unknown]
            .map { s in Slice(severity: s, count: rows.filter { $0.vuln.severity == s }.count) }
            .filter { $0.count > 0 }
    }

    var body: some View {
        let list = slices
        let total = max(1, list.reduce(0) { $0 + $1.count })
        HStack(spacing: 12) {
            GeometryReader { geo in
                let gaps = CGFloat(max(0, list.count - 1)) * 1.5
                HStack(spacing: 1.5) {
                    ForEach(list) { s in
                        let dim = !filter.severities.isEmpty && !filter.severities.contains(s.severity)
                        RoundedRectangle(cornerRadius: 2)
                            .fill(s.severity.tint.opacity(dim ? 0.18 : 0.9))
                            .frame(width: max(2, (geo.size.width - gaps) * CGFloat(s.count) / CGFloat(total)))
                            .onTapGesture { withAnimation(.snappy(duration: 0.2)) { filter.toggle(s.severity) } }
                            .help("\(plural(s.count, "advisory", "advisories")) · \(s.severity.title) · \(Int((Double(s.count) / Double(total) * 100).rounded()))% of all")
                    }
                }
            }
            .frame(height: 10)
            HStack(spacing: 10) {
                ForEach(list) { s in chip(s, total: total) }
            }
            .fixedSize()
        }
    }

    /// The count and its share: 12 criticals out of 40 is a different week from 12 out of 400.
    func chip(_ s: Slice, total: Int) -> some View {
        let on = filter.severities.contains(s.severity)
        let pct = Int((Double(s.count) / Double(total) * 100).rounded())
        return Button {
            withAnimation(.snappy(duration: 0.2)) { filter.toggle(s.severity) }
        } label: {
            HStack(spacing: 5) {
                Circle().fill(s.severity.tint).frame(width: 7, height: 7)
                Text("\(s.severity.title) \(s.count)").font(.system(size: 11, weight: on ? .semibold : .regular)).monospacedDigit()
                    .foregroundStyle(on ? Color.primary : Color.secondary)
                Text("\(pct)%").font(.system(size: 10.5).monospacedDigit()).foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(Capsule().fill(on ? s.severity.tint.opacity(0.14) : Color.clear))
            .overlay(Capsule().stroke(on ? s.severity.tint.opacity(0.35) : Color.clear))
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
    }
}

// MARK: - In-cell bars

/// Severity and its score in one cell: the word, with the CVSS bar behind it and the number
/// at the end. Two columns' worth of meaning in one column's width.
struct SeverityCell: View {
    var severity: Severity
    var cvss: Double

    var body: some View {
        // A filled block behind every row turns a table of criticals into a wall of colour.
        // A short rule carries the same score and leaves the text readable.
        HStack(spacing: 6) {
            Capsule().fill(severity.tint).frame(width: 3)
            Text(severity.title).font(.system(size: 11.5))
            Spacer(minLength: 2)
            if cvss >= 0 {
                ZStack(alignment: .leading) {
                    Capsule().fill(Color.primary.opacity(0.07)).frame(width: 26, height: 3)
                    Capsule().fill(severity.tint.opacity(0.8)).frame(width: max(1, 26 * min(1, cvss / 10)), height: 3)
                }
                Text(String(format: "%.1f", cvss)).font(.system(size: 11).monospacedDigit()).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 3)
    }
}

/// The signals that change what a row means, in the margin where the flame already was:
/// exploited in the wild, public exploit code, and reachable on this Mac right now.
struct SignalCell: View {
    var row: LedgerRow

    var body: some View {
        HStack(spacing: 3) {
            if row.vuln.isKEV {
                Image(systemName: "flame.fill").foregroundStyle(.red)
                    .help("Exploited in the wild (\(row.vuln.kev?.listName ?? "KEV"))")
            }
            if row.vuln.hasPublicExploit {
                Image(systemName: "hammer.fill").foregroundStyle(.purple)
                    .help("Public exploit code: " + (row.vuln.publicExploits ?? []).joined(separator: ", "))
            }
            if !row.exposure.isEmpty {
                Image(systemName: row.exposure.hasPrefix("listening") ? "antenna.radiowaves.left.and.right" : row.exposure == "running" ? "play.circle" : "power")
                    .foregroundStyle(.orange).help("On this Mac: \(row.exposure)")
            }
        }
        .font(.system(size: 10.5))
    }
}

/// A score in a table cell reads as a number you have to interpret; the bar behind it is the
/// interpretation. Width is the score against its own ceiling.
struct ScoreCell: View {
    var value: Double
    var ceiling: Double
    var text: String
    var tint: Color

    var body: some View {
        ZStack(alignment: .leading) {
            GeometryReader { geo in
                RoundedRectangle(cornerRadius: 2.5)
                    .fill(tint.opacity(0.18))
                    .frame(width: max(0, min(1, value / ceiling)) * geo.size.width)
                    .frame(maxHeight: .infinity)
            }
            Text(text).font(.system(size: 11.5).monospacedDigit()).padding(.leading, 3)
        }
    }
}

// MARK: - Carriers

/// Three hundred rows of "golang.org/x/crypto (in ollama)" are one thing to update, not three
/// hundred problems. Every picture below is drawn on these: one entry per thing you would
/// actually touch, with the advisories riding on it.
struct CarrierSummary: Identifiable {
    var key: String
    var name: String
    var detail: String
    var rows: [LedgerRow]
    var severity: Severity
    var kev: Int
    var reachable: Bool
    var id: String { key.isEmpty ? "\u{2026}rest" : key }
    var count: Int { rows.count }
    var value: Double { Double(rows.count) }
    func count(_ s: Severity) -> Int { rows.filter { $0.vuln.severity == s }.count }

    static func group(_ rows: [LedgerRow]) -> [CarrierSummary] {
        var order: [String] = [], map: [String: [LedgerRow]] = [:]
        for r in rows {
            if map[r.carrier] == nil { order.append(r.carrier) }
            map[r.carrier, default: []].append(r)
        }
        return order.map { k in summary(key: k, name: shortModule(k), rows: map[k]!) }
            .sorted { ($0.count, $0.severity.rank) > ($1.count, $1.severity.rank) }
    }

    static func summary(key: String, name: String, rows: [LedgerRow]) -> CarrierSummary {
        let kinds = Set(rows.map(\.finding.package.ecosystem.title))
        return CarrierSummary(key: key, name: name,
                              detail: kinds.count == 1 ? (kinds.first ?? "") : "\(kinds.count) kinds",
                              rows: rows,
                              severity: rows.map(\.vuln.severity).max() ?? .unknown,
                              kev: rows.filter { $0.vuln.isKEV }.count,
                              reachable: rows.contains(where: \.reachable))
    }

    /// Keep the big ones separate and fold the long tail into one honest entry.
    static func capped(_ list: [CarrierSummary], at limit: Int) -> [CarrierSummary] {
        guard list.count > limit else { return list }
        let head = Array(list.prefix(limit - 1)), tail = list.dropFirst(limit - 1)
        let rest = summary(key: "", name: "\(tail.count) smaller", rows: tail.flatMap(\.rows))
        return head + [rest]
    }
}

/// The sentence a concentration chart is really making.
func concentration(_ list: [CarrierSummary], total: Int) -> String {
    guard total > 0, !list.isEmpty else { return "" }
    var running = 0, n = 0
    for c in list {
        running += c.count; n += 1
        if Double(running) / Double(total) >= 0.8 { break }
    }
    if n == list.count { return "\(plural(total, "advisory", "advisories")) spread across \(plural(list.count, "package"))." }
    return "\(n) of \(list.count) packages carry \(Int((Double(running) / Double(total) * 100).rounded()))% of the \(total) advisories."
}

// MARK: - Bars

/// Ranked bars. A treemap has to shrink a label to fit its tile, so a package holding three
/// quarters of the advisories squeezes the rest into slivers; here the name and the count sit
/// outside the geometry and stay readable however lopsided the data is. Each bar is split by
/// severity, so the shape of a package's problem shows in the bar itself.
struct AdvisoryBars: View {
    var rows: [LedgerRow]
    var open: (String) -> Void
    @State private var hovered: String?

    var body: some View {
        let list = CarrierSummary.capped(CarrierSummary.group(rows), at: 24)
        let top = max(1, list.map(\.count).max() ?? 1)
        VStack(alignment: .leading, spacing: 8) {
            Text(rows.isEmpty ? "Nothing matches the filters above." : concentration(list, total: rows.count))
                .font(.system(size: 11.5)).foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(list) { c in row(c, top: top) }
                }
                .padding(.bottom, 8)
            }
        }
        .padding(.horizontal, 28).padding(.bottom, 16)
    }

    func row(_ c: CarrierSummary, top: Int) -> some View {
        let on = hovered == c.id
        return Button {
            if !c.key.isEmpty { open(c.key) }
        } label: {
            HStack(spacing: 10) {
                HStack(spacing: 4) {
                    if c.kev > 0 { Image(systemName: "flame.fill").font(.system(size: 9)).foregroundStyle(.red) }
                    if c.reachable { Image(systemName: "antenna.radiowaves.left.and.right").font(.system(size: 9)).foregroundStyle(.orange) }
                    Text(c.name).font(.system(size: 12, weight: on ? .semibold : .regular)).lineLimit(1).truncationMode(.middle)
                }
                .frame(width: 190, alignment: .leading)
                GeometryReader { geo in
                    let full = geo.size.width * CGFloat(c.count) / CGFloat(top)
                    HStack(spacing: 0) {
                        ForEach(Severity.allCases, id: \.self) { s in
                            let n = c.count(s)
                            if n > 0 {
                                Rectangle().fill(s.tint.opacity(0.85))
                                    .frame(width: full * CGFloat(n) / CGFloat(max(1, c.count)))
                            }
                        }
                        Spacer(minLength: 0)
                    }
                    .clipShape(RoundedRectangle(cornerRadius: 3))
                }
                .frame(height: 14)
                Text(c.count.formatted()).font(.system(size: 12, weight: .medium)).monospacedDigit()
                    .frame(width: 40, alignment: .trailing)
                Text(c.detail).font(.system(size: 10.5)).foregroundStyle(.tertiary)
                    .frame(width: 110, alignment: .leading).lineLimit(1)
            }
            .padding(.vertical, 2).padding(.horizontal, 6)
            .background(RoundedRectangle(cornerRadius: 6).fill(on ? Color.primary.opacity(0.04) : .clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { inside in hovered = inside ? c.id : (hovered == c.id ? nil : hovered) }
        .help("\(c.name) \u{00b7} \(plural(c.count, "advisory", "advisories"))" + (c.kev > 0 ? ", \(c.kev) exploited" : ""))
    }
}

// MARK: - Dots

/// One square per advisory, grouped by what carries it. Nothing is scaled or binned, so a
/// hundred and eight of them look like a hundred and eight — the honest version of a count,
/// and the only one of these views where a single exploited square is still its own object.
struct AdvisoryDots: View {
    var rows: [LedgerRow]
    var open: (String) -> Void
    @Environment(AppModel.self) private var model

    var body: some View {
        let list = CarrierSummary.capped(CarrierSummary.group(rows), at: 20)
        VStack(alignment: .leading, spacing: 8) {
            Text(rows.isEmpty ? "Nothing matches the filters above." : "One square per advisory, grouped by what carries it. Click a square to open it.")
                .font(.system(size: 11.5)).foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(list) { c in block(c) }
                }
                .padding(.bottom, 8)
            }
        }
        .padding(.horizontal, 28).padding(.bottom, 16)
    }

    func block(_ c: CarrierSummary) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 5) {
                if c.kev > 0 { Image(systemName: "flame.fill").font(.system(size: 9)).foregroundStyle(.red) }
                if c.reachable { Image(systemName: "antenna.radiowaves.left.and.right").font(.system(size: 9)).foregroundStyle(.orange) }
                Button(c.name) { if !c.key.isEmpty { open(c.key) } }
                    .buttonStyle(.plain).font(.system(size: 12, weight: .medium))
                Text(c.count.formatted()).font(.system(size: 11).monospacedDigit()).foregroundStyle(.secondary)
                Text(c.detail).font(.system(size: 10.5)).foregroundStyle(.tertiary)
            }
            FlowLayout(spacing: 3) {
                ForEach(c.rows.sorted { $0.vuln.priority > $1.vuln.priority }) { r in
                    DotMark(row: r) { model.selectedVuln = VulnSelection(finding: r.finding, vuln: r.vuln) }
                }
            }
        }
    }
}

struct DotMark: View {
    var row: LedgerRow
    var open: () -> Void
    @State private var hover = false

    var body: some View {
        RoundedRectangle(cornerRadius: 2)
            .fill(row.vuln.severity.tint.opacity(hover ? 1 : 0.8))
            .frame(width: 9, height: 9)
            .overlay {
                if row.vuln.isKEV {
                    RoundedRectangle(cornerRadius: 2).stroke(Color.primary.opacity(0.85), lineWidth: 1.5)
                }
            }
            .scaleEffect(hover ? 1.35 : 1)
            .onHover { hover = $0 }
            .onTapGesture(perform: open)
            .help("\(row.advisory) \u{00b7} \(row.vuln.severity.title)" + (row.vuln.isKEV ? " \u{00b7} exploited in the wild" : "")
                  + (row.cvss >= 0 ? " \u{00b7} CVSS \(String(format: "%.1f", row.cvss))" : ""))
    }
}

/// Left-to-right, wrap at the edge. SwiftUI has no flow stack of its own.
struct FlowLayout: Layout {
    var spacing: CGFloat = 3

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let limit = proposal.width ?? 400
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0
        for v in subviews {
            let size = v.sizeThatFits(.unspecified)
            if x + size.width > limit, x > 0 { x = 0; y += rowHeight + spacing; rowHeight = 0 }
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
        return CGSize(width: limit, height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, rowHeight: CGFloat = 0
        for v in subviews {
            let size = v.sizeThatFits(.unspecified)
            if x + size.width > bounds.maxX, x > bounds.minX { x = bounds.minX; y += rowHeight + spacing; rowHeight = 0 }
            v.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}

// MARK: - Map

/// Area as count. Reads well when the load is spread; when one package holds most of it the
/// tail becomes slivers, which is what the bars are for.
struct AdvisoryMap: View {
    var rows: [LedgerRow]
    var open: (String) -> Void
    @State private var hovered: String?

    struct Placed: Identifiable {
        var tile: CarrierSummary
        var rect: CGRect
        var id: String { tile.id }
    }

    var body: some View {
        let all = CarrierSummary.group(rows)
        let cells = CarrierSummary.capped(all, at: 30)
        VStack(alignment: .leading, spacing: 8) {
            Text(rows.isEmpty
                 ? "Nothing matches the filters above."
                 : "\(plural(rows.count, "advisory", "advisories")) across \(plural(all.count, "package")). Tile size is how many ride on it; colour is the worst one.")
                .font(.system(size: 11.5)).foregroundStyle(.secondary)
            GeometryReader { geo in
                let placed = Treemap.layout(cells, in: CGRect(origin: .zero, size: geo.size)) { $0.value }
                    .map { Placed(tile: $0.0, rect: $0.1) }
                ZStack(alignment: .topLeading) {
                    ForEach(placed) { p in
                        TileView(tile: p.tile, hovered: hovered == p.id)
                            .frame(width: max(0, p.rect.width - 2), height: max(0, p.rect.height - 2))
                            .offset(x: p.rect.minX + 1, y: p.rect.minY + 1)
                            .onHover { inside in hovered = inside ? p.id : (hovered == p.id ? nil : hovered) }
                            .onTapGesture { if !p.tile.key.isEmpty { open(p.tile.key) } }
                    }
                }
            }
        }
        .padding(.horizontal, 28).padding(.bottom, 20)
    }
}

/// One tile: the name while there is room for it, the count, and a flame when any of the
/// advisories on it are being exploited.
struct TileView: View {
    var tile: CarrierSummary
    var hovered: Bool

    var body: some View {
        GeometryReader { geo in
            let wide = geo.size.width >= 58, tall = geo.size.height >= 30
            let roomy = wide && geo.size.height >= 52
            ZStack(alignment: .topLeading) {
                RoundedRectangle(cornerRadius: 5)
                    .fill(tile.severity.tint.opacity(tile.kev > 0 ? 0.92 : 0.68))
                RoundedRectangle(cornerRadius: 5)
                    .stroke(hovered ? Color.primary.opacity(0.55) : Color.white.opacity(0.18), lineWidth: hovered ? 1.5 : 0.5)
                VStack(alignment: .leading, spacing: 2) {
                    if wide, tall {
                        HStack(spacing: 3) {
                            if tile.kev > 0 { Image(systemName: "flame.fill").font(.system(size: 9)) }
                            if tile.reachable { Image(systemName: "antenna.radiowaves.left.and.right").font(.system(size: 9)) }
                            Text(tile.name).font(.system(size: 11, weight: .semibold)).lineLimit(1).truncationMode(.middle)
                        }
                        Text(tile.count.formatted()).font(.system(size: roomy ? 17 : 12, weight: .semibold)).monospacedDigit()
                        if roomy {
                            Text(tile.kev > 0 ? "\(tile.kev) exploited" : tile.detail)
                                .font(.system(size: 10)).opacity(0.8).lineLimit(1)
                        }
                    } else {
                        Text(tile.count.formatted()).font(.system(size: 10, weight: .semibold)).monospacedDigit()
                    }
                }
                .foregroundStyle(.white)
                .padding(.horizontal, 6).padding(.vertical, 5)
            }
        }
        .help("\(tile.name) \u{2014} \(plural(tile.count, "advisory", "advisories")), worst \(tile.severity.title.lowercased())"
              + (tile.kev > 0 ? ", \(tile.kev) exploited in the wild" : "")
              + (tile.reachable ? ", running or listening here" : ""))
    }
}

/// Binary-split treemap: halve the list by weight, split the rectangle the same way along its
/// longer side, recurse. Keeps tiles close to square without the bookkeeping of squarified.
enum Treemap {
    static func layout<T>(_ items: [T], in rect: CGRect, value: (T) -> Double) -> [(T, CGRect)] {
        guard !items.isEmpty, rect.width > 0, rect.height > 0 else { return [] }
        if items.count == 1 { return [(items[0], rect)] }
        let total = items.reduce(0) { $0 + max(0.0001, value($1)) }
        var acc = 0.0, cut = 0
        for (i, it) in items.enumerated() {
            let v = max(0.0001, value(it))
            if acc + v > total / 2, i > 0 { break }
            acc += v; cut = i + 1
        }
        cut = min(max(1, cut), items.count - 1)
        acc = items[..<cut].reduce(0) { $0 + max(0.0001, value($1)) }
        let head = Array(items[..<cut]), tail = Array(items[cut...])
        let frac = min(0.92, max(0.08, acc / total))
        if rect.width >= rect.height {
            let w = rect.width * frac
            return layout(head, in: CGRect(x: rect.minX, y: rect.minY, width: w, height: rect.height), value: value)
                + layout(tail, in: CGRect(x: rect.minX + w, y: rect.minY, width: rect.width - w, height: rect.height), value: value)
        } else {
            let h = rect.height * frac
            return layout(head, in: CGRect(x: rect.minX, y: rect.minY, width: rect.width, height: h), value: value)
                + layout(tail, in: CGRect(x: rect.minX, y: rect.minY + h, width: rect.width, height: rect.height - h), value: value)
        }
    }
}
