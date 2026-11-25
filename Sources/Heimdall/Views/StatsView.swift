import HeimdallCore
import SwiftUI

/// How fast flaws actually get fixed here, measured rather than felt. Every row is one
/// advisory on one installed version, with the three gaps that matter between its clocks.
struct StatsPage: View {
    @Environment(AppModel.self) private var model
    @AppStorage("statsWindow") private var days = 180

    var body: some View {
        let all = model.lag.filter { ($0.firstSeen ?? .distantPast) >= Date().addingTimeInterval(-Double(days) * 86400) }
        let packaging = all.compactMap(\.packagingDays)
        let exposure = all.compactMap(\.exposureDays)
        let dwell = all.compactMap(\.dwellDays)
        ModernPageFrame(page: .stats) {
            HStack(spacing: 12) {
                Picker("", selection: $days) {
                    Text("90 days").tag(90)
                    Text("6 months").tag(180)
                    Text("12 months").tag(365)
                    Text("Everything").tag(36500)
                }
                .labelsHidden().fixedSize()
                Spacer()
                Text("\(plural(all.count, "advisory", "advisories")) with a recorded history")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            }
            .controlSize(.small)

            // Release lag needs no advisory and no waiting, so it is the one part of this
            // page that is full on the first scan. It leads for that reason.
            if !model.freshness.isEmpty {
                let behind = model.freshness.compactMap(\.behindDays)
                ModernHeading(title: "How Far Behind This Mac Is", count: model.freshness.count, tint: .mint)
                Text("For every formula with an update waiting, the days between the version you have being bottled and the newest one being bottled. Both dates come from Homebrew's registry, so this is history, not a forecast.")
                    .font(.system(size: 12.5)).foregroundStyle(.secondary).padding(.bottom, 8)
                HStack(spacing: 12) {
                    StatCard(title: "Median formula is behind by", days: behind, tint: .orange,
                             caption: "days of releases between the installed bottle and the newest one")
                    StatCard(title: "Worst case", days: behind.max().map { [$0] } ?? [], tint: .red,
                             caption: "the formula that has gone longest without being updated here")
                }
                .padding(.bottom, 10)
                ForEach(model.freshness.prefix(12)) { f in FreshnessRow(item: f) }
            }

            if model.lag.isEmpty {
                empty
            } else {
                HStack(spacing: 12) {
                    StatCard(title: "Homebrew took", days: packaging, tint: .orange,
                             caption: "from the advisory being published to a bottle you could install")
                    StatCard(title: "You took", days: exposure, tint: .blue,
                             caption: "from that bottle existing to the advisory going away, or to today if it is still here")
                    StatCard(title: "Open here", days: dwell, tint: .teal,
                             caption: "from Heimdall first seeing it to it going away")
                }
                .padding(.top, 14)

                let lanes = all.filter { $0.packagingDays != nil || $0.exposureDays != nil }
                    .sorted { ($0.published ?? .distantPast) > ($1.published ?? .distantPast) }
                if !lanes.isEmpty {
                    ModernHeading(title: "Where the days went", count: lanes.count, tint: .mint)
                    Text("Each lane is one advisory. Orange is the wait for Homebrew to bottle a fix; blue is the wait for this Mac to install it.")
                        .font(.system(size: 12.5)).foregroundStyle(.secondary).padding(.bottom, 6)
                    let span = max(1, lanes.compactMap { ($0.packagingDays ?? 0) + ($0.exposureDays ?? 0) }.max() ?? 1)
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(Array(lanes.prefix(40))) { r in LagLane(record: r, span: span) }
                    }
                }

                let unresolved = all.filter { $0.resolved == nil && $0.bottled != nil }
                if !unresolved.isEmpty {
                    ModernHeading(title: "Still Waiting On You", count: unresolved.count, tint: .red)
                    Text("A fix has been installable for these since the date shown, and this Mac is still on the old version.")
                        .font(.system(size: 12.5)).foregroundStyle(.secondary).padding(.bottom, 6)
                    ForEach(unresolved.sorted { ($0.exposureDays ?? 0) > ($1.exposureDays ?? 0) }.prefix(10)) { r in
                        WaitingRow(record: r)
                    }
                }

                ModernHeading(title: "How This Is Measured", tint: .gray)
                ForEach(Self.method, id: \.self) { line in
                    Text(line).font(.system(size: 12.5)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true).padding(.bottom, 5)
                }
            }
        }
    }

    var empty: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No advisory timings yet.").font(.system(size: 15))
            Text("A row is written for every advisory at the end of each scan, with the day it was published, the day Homebrew bottled a fix, and the day this Mac installed the version it is on. Rescan (\u{2318}R) to start the record.")
                .font(.system(size: 13)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Text("Dates are not backfilled: the record starts from the first scan after this version, so the numbers thicken over the next few weeks.")
                .font(.system(size: 13)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .padding(.top, 24)
    }

    static let method = [
        "Published comes from the advisory itself (OSV or NVD). Bottled is the day a bottle for the first fixed version appeared on Homebrew's registry \u{2014} the day it became installable, not the day upstream tagged it. Installed is the timestamp Homebrew wrote into the keg when this Mac poured it.",
        "Medians, not averages: one advisory that sat for a year would otherwise speak for all of them.",
        "An advisory with no bottled date is left out of the first two figures. That is usually a formula with no bottle for the fixed version, or a fix that is still only a commit upstream.",
    ]
}

/// A median with the spread under it, because a single number hides whether the tail is bad.
struct StatCard: View {
    var title: String
    var days: [Int]
    var tint: Color
    var caption: String

    var body: some View {
        let sorted = days.sorted()
        let median = sorted.isEmpty ? nil : sorted[sorted.count / 2]
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
            HStack(alignment: .firstTextBaseline, spacing: 5) {
                Text(median.map { "\($0)" } ?? "\u{2014}")
                    .font(.system(size: 26, weight: .semibold)).monospacedDigit()
                    .foregroundStyle(median == nil ? AnyShapeStyle(.tertiary) : AnyShapeStyle(tint))
                Text(median == 1 ? "day" : "days").font(.system(size: 12.5)).foregroundStyle(.secondary)
                Spacer(minLength: 2)
                if let worst = sorted.last, sorted.count > 1 {
                    Text("worst \(worst)").font(.system(size: 10.5).monospacedDigit()).foregroundStyle(.tertiary)
                }
            }
            if !sorted.isEmpty {
                // One tick per advisory, placed by its own value: the shape of the spread.
                GeometryReader { geo in
                    let top = max(1, sorted.last ?? 1)
                    ZStack(alignment: .leading) {
                        Capsule().fill(Color.primary.opacity(0.06)).frame(height: 4)
                        ForEach(Array(sorted.enumerated()), id: \.offset) { _, d in
                            Circle().fill(tint.opacity(0.7)).frame(width: 5, height: 5)
                                .offset(x: (geo.size.width - 5) * CGFloat(d) / CGFloat(top))
                        }
                    }
                    .frame(height: 6)
                }
                .frame(height: 8)
            }
            Text(caption).font(.system(size: 11)).foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
            Text(sorted.isEmpty ? "no rows yet" : plural(sorted.count, "advisory", "advisories"))
                .font(.system(size: 10.5)).foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(nsColor: .textBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.primary.opacity(0.07)))
    }
}

/// One advisory's two waits, drawn end to end against the worst case on the page.
struct LagLane: View {
    var record: Lag.Record
    var span: Int
    @State private var hover = false

    var body: some View {
        let r = record
        let pack = r.packagingDays ?? 0, mine = r.exposureDays ?? 0
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 1) {
                Text(r.package).font(.system(size: 12, weight: .medium)).lineLimit(1).truncationMode(.middle)
                Text(r.advisory).font(.system(size: 10.5)).foregroundStyle(.secondary).lineLimit(1)
            }
            .frame(width: 180, alignment: .leading)
            GeometryReader { geo in
                HStack(spacing: 1) {
                    if pack > 0 {
                        RoundedRectangle(cornerRadius: 2).fill(Color.orange.opacity(0.8))
                            .frame(width: max(2, geo.size.width * CGFloat(pack) / CGFloat(span)))
                    }
                    if mine > 0 {
                        RoundedRectangle(cornerRadius: 2).fill((r.resolved == nil ? Color.red : Color.blue).opacity(0.8))
                            .frame(width: max(2, geo.size.width * CGFloat(mine) / CGFloat(span)))
                    }
                    if pack == 0 && mine == 0 {
                        Circle().fill(Color.green).frame(width: 6, height: 6)
                    }
                    Spacer(minLength: 0)
                }
            }
            .frame(height: 12)
            Text("\(pack + mine)d").font(.system(size: 11).monospacedDigit())
                .foregroundStyle(.secondary).frame(width: 40, alignment: .trailing)
            if r.resolved == nil { ThingsTag(text: "still open", tint: .red) }
        }
        .padding(.vertical, 3).padding(.horizontal, 6)
        .background(RoundedRectangle(cornerRadius: 6).fill(hover ? Color.primary.opacity(0.04) : .clear))
        .onHover { hover = $0 }
        .help(detail)
    }

    var detail: String {
        var parts = ["\(record.package) \(record.version) \u{00b7} \(record.advisory)"]
        if let p = record.published { parts.append("published \(p.shortDay)") }
        if let b = record.bottled { parts.append("bottled \(b.shortDay)") }
        if let v = record.fixedVersion { parts.append("fixed in \(v)") }
        if let i = record.installed { parts.append("this version installed \(i.shortDay)") }
        if let r = record.resolved { parts.append("gone by \(r.shortDay)") }
        return parts.joined(separator: " \u{00b7} ")
    }
}

/// An advisory whose fix has been sitting on the shelf. The number is the point.
struct WaitingRow: View {
    var record: Lag.Record

    var body: some View {
        let r = record
        HStack(spacing: 10) {
            Image(systemName: "clock.badge.exclamationmark").foregroundStyle(.red).frame(width: 16)
            Text(r.package).font(.system(size: 13.5)).lineLimit(1)
            Text(r.advisory).font(.system(size: 12.5)).foregroundStyle(.secondary)
            if let v = r.fixedVersion {
                Text("\(r.version) \u{2192} \(v)").font(.system(size: 12, design: .monospaced)).foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            if let b = r.bottled { Text("bottled \(b.shortDay)").font(.system(size: 11.5)).foregroundStyle(.tertiary) }
            if let d = r.exposureDays { ThingsTag(text: "\(d)d on the shelf", tint: d >= 14 ? .red : .orange, filled: d >= 30) }
        }
        .padding(.vertical, 5).padding(.horizontal, 10)
    }
}


/// One formula and the gap between the bottle it is on and the newest one.
struct FreshnessRow: View {
    var item: Lag.Freshness
    @State private var hover = false

    var body: some View {
        let f = item
        HStack(spacing: 10) {
            Image(systemName: "shippingbox").foregroundStyle(.secondary).frame(width: 16)
            Text(f.formula).font(.system(size: 13.5)).lineLimit(1).frame(width: 150, alignment: .leading)
            Text("\(f.installed) → \(f.latest)").font(.system(size: 12, design: .monospaced)).foregroundStyle(.secondary)
                .lineLimit(1).truncationMode(.middle)
            Spacer(minLength: 8)
            if let b = f.installedBottled { Text("yours \(b.shortDay)").font(.system(size: 11)).foregroundStyle(.tertiary) }
            if let d = f.behindDays {
                ThingsTag(text: "\(d)d behind", tint: d >= 180 ? .red : d >= 60 ? .orange : .secondary, filled: d >= 365)
            } else {
                ThingsTag(text: "no bottle date")
            }
        }
        .padding(.vertical, 5).padding(.horizontal, 10)
        .background(RoundedRectangle(cornerRadius: 6).fill(hover ? Color.primary.opacity(0.04) : .clear))
        .onHover { hover = $0 }
        .help(detail)
    }

    var detail: String {
        var parts = ["\(item.formula) \(item.installed)"]
        if let b = item.installedBottled { parts.append("that version was bottled \(b.shortDay)") }
        if let i = item.installedHere { parts.append("you installed it \(i.shortDay)") }
        if let l = item.latestBottled { parts.append("\(item.latest) was bottled \(l.shortDay)") }
        if let d = item.shelfDays { parts.append("\(d) days on the shelf since") }
        return parts.joined(separator: " · ")
    }
}
