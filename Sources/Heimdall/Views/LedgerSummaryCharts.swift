import Charts
import HeimdallCore
import SwiftUI

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
