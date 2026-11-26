import Charts
import HeimdallCore
import SwiftUI

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
