import HeimdallCore
import SwiftUI

/// What narrows the inventory table: a kind, a coverage state, or one of the standing worries.
struct InventoryFilter: Equatable {
    var kind: Ecosystem?
    var coverage: PackageCoverage.State?
    var outdated = false
    var unmaintained = false
    var vulnerable = false
    /// Everything a check never reached, whatever the reason — the Brief's banner arrives here.
    var unchecked = false

    var active: Bool { kind != nil || coverage != nil || outdated || unmaintained || vulnerable || unchecked }

    func matches(_ p: Package, vulnerable ids: Set<String>) -> Bool {
        if let kind, p.ecosystem != kind { return false }
        if let coverage, (p.coverage?.state ?? .pending) != coverage { return false }
        if outdated, !p.outdated { return false }
        if unmaintained, p.maintenance?.terminal != true { return false }
        if self.vulnerable, !ids.contains(p.id) { return false }
        if unchecked, p.coverage?.state == .checked || p.coverage?.state == .cached { return false }
        return true
    }

    var summary: String {
        var parts: [String] = []
        if let kind { parts.append(kind.title) }
        if let coverage { parts.append(coverage.title.lowercased()) }
        if outdated { parts.append("update ready") }
        if unmaintained { parts.append("unmaintained") }
        if vulnerable { parts.append("with advisories") }
        if unchecked { parts.append("never checked") }
        return parts.joined(separator: " · ")
    }
}

/// The inventory's point is breadth: 863 packages read, and how much of that Heimdall could
/// actually check. A name-sorted table answers neither question, so the band answers both
/// before the table starts — and every part of it narrows the table.
struct InventoryOverview: View {
    var packages: [Package]
    var vulnerableIDs: Set<String>
    var exploitedIDs: Set<String>
    @Binding var filter: InventoryFilter
    /// Owned by the page, because the page needs the height this implies before laying out.
    @Binding var expanded: Bool

    /// Coverage in the order a reader cares about: what was checked, then why the rest wasn't.
    static let states: [PackageCoverage.State] = [.checked, .cached, .pending, .noMapping, .unavailable, .disabled]

    func tint(_ s: PackageCoverage.State) -> Color {
        switch s {
        // Deliberately not green: these are reach, not health. What the checks found is the
        // line above, and that one is allowed to be green.
        case .checked: return .blue
        case .cached: return .teal
        case .pending: return .blue
        case .noMapping: return .orange
        case .unavailable: return .red
        case .disabled: return .secondary
        }
    }

    struct Slice: Identifiable {
        var state: PackageCoverage.State
        var count: Int
        var id: String { state.rawValue }
    }

    /// Everything the band shows about one kind, counted once.
    struct KindTally: Identifiable {
        var kind: Ecosystem
        var total = 0
        var checked = 0
        var vulnerable = 0
        var outdated = 0
        var id: Ecosystem { kind }
    }

    /// A single walk of the inventory. With 800-odd packages and a card per ecosystem, the
    /// per-card filters this replaces were running tens of thousands of comparisons on every
    /// layout pass.
    struct Tally {
        var states: [PackageCoverage.State: Int] = [:]
        var kinds: [Ecosystem: KindTally] = [:]
        var checked = 0, vulnerable = 0, exploited = 0, outdated = 0, unmaintained = 0

        init(_ packages: [Package], vulnerableIDs: Set<String>, exploitedIDs: Set<String>) {
            for p in packages {
                let state = p.coverage?.state ?? .pending
                states[state, default: 0] += 1
                let isChecked = state == .checked || state == .cached
                let isVuln = vulnerableIDs.contains(p.id)
                if isChecked { checked += 1 }
                if isVuln { vulnerable += 1 }
                if exploitedIDs.contains(p.id) { exploited += 1 }
                if p.outdated { outdated += 1 }
                if p.maintenance?.terminal == true { unmaintained += 1 }
                var k = kinds[p.ecosystem] ?? KindTally(kind: p.ecosystem)
                k.total += 1
                if isChecked { k.checked += 1 }
                if isVuln { k.vulnerable += 1 }
                if p.outdated { k.outdated += 1 }
                kinds[p.ecosystem] = k
            }
        }

        var slices: [Slice] {
            InventoryOverview.states.compactMap { s in
                (states[s] ?? 0) > 0 ? Slice(state: s, count: states[s] ?? 0) : nil
            }
        }
        var orderedKinds: [KindTally] { Ecosystem.allCases.compactMap { kinds[$0] } }
    }

    var body: some View {
        let tally = Tally(packages, vulnerableIDs: vulnerableIDs, exploitedIDs: exploitedIDs)
        let checked = tally.checked, vuln = tally.vulnerable, exploited = tally.exploited
        // The headline is what the checks found. Coverage is how far they reached, which is a
        // caveat on the finding rather than a verdict of its own.
        let share = Int((Double(vuln) / Double(max(1, checked)) * 100).rounded())
        let tone: Color = exploited > 0 ? .red : vuln > 0 ? .orange : .green
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(vuln == 0 ? "None" : "\(share)%")
                    .font(.system(size: 22, weight: .semibold)).monospacedDigit().foregroundStyle(tone)
                Text(vuln == 0
                     ? "of the \(checked.formatted()) packages Heimdall could check carry an advisory"
                     : "of the \(checked.formatted()) packages Heimdall could check carry an advisory — \(vuln.formatted()) of them"
                        + (exploited > 0 ? ", \(exploited) exploited in the wild" : ""))
                    .font(.system(size: 12.5)).foregroundStyle(.secondary)
                Spacer()
                if filter.active {
                    Button {
                        withAnimation(.snappy(duration: 0.2)) { filter = InventoryFilter() }
                    } label: { Label("Showing \(filter.summary)", systemImage: "xmark.circle.fill") }
                        .buttonStyle(.borderless).font(.system(size: 11.5, weight: .medium)).foregroundStyle(.secondary)
                }
                Button(expanded ? "Hide" : "Show") { withAnimation(.snappy(duration: 0.22)) { expanded.toggle() } }
                    .buttonStyle(.borderless).font(.system(size: 11.5, weight: .medium))
            }
            if expanded {
                // Inside its own scroller: whatever this adds up to, it cannot argue with
                // the table for height. Three attempts at letting SwiftUI negotiate this
                // ended with the page pushed off the top of the window.
                ScrollView(.vertical, showsIndicators: false) {
                    VStack(alignment: .leading, spacing: 10) {
                        explanation(tally: tally)
                        coverageStrip(tally.slices)
                        kindGrid(tally.orderedKinds)
                        worries(tally)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .padding(.horizontal, 28).padding(.bottom, 10)
    }

    /// What the band costs the table, decided here rather than discovered during layout.
    static func height(expanded: Bool) -> CGFloat { expanded ? 236 : 40 }

    /// What the headline number is and is not. Two percentages on one screen — how many were
    /// checked, how many came back bad — invite the wrong reading unless the page says which
    /// is which, so it says it.
    func explanation(tally: Tally) -> some View {
        let checked = tally.checked, missed = packages.count - tally.checked
        var why: [String] = []
        func n(_ s: PackageCoverage.State) -> Int { tally.states[s] ?? 0 }
        if n(.noMapping) > 0 { why.append("\(n(.noMapping)) no product mapping") }
        why += PackageCoverage.unavailableBreakdown(packages)
        if n(.disabled) > 0 { why.append("\(n(.disabled)) off in Settings") }
        if n(.pending) > 0 { why.append("\(n(.pending)) still checking") }
        let read = "Heimdall read \(plural(packages.count, "package")) and matched \(checked.formatted()) of them against OSV, NVD, CISA KEV and vendor advisories. "
            + (tally.vulnerable == 0
               ? "None came back with an advisory that applies to the version installed here."
               : "\(tally.vulnerable.formatted()) came back with an advisory that applies to the version installed here"
                 + (tally.exploited > 0 ? ", and \(tally.exploited) of those are on a known-exploited list." : "."))
        let gap = missed == 0 ? nil
            : "\(missed.formatted()) unchecked — unknown, not clean" + (why.isEmpty ? "." : ": " + why.joined(separator: " · "))
        return VStack(alignment: .leading, spacing: 4) {
            Text(read).font(.system(size: 11.5)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let gap {
                Text(gap).font(.system(size: 11.5)).foregroundStyle(.orange.opacity(0.9))
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// One bar for the whole inventory, split by coverage state, with the states as toggles.
    func coverageStrip(_ list: [Slice]) -> some View {
        let total = max(1, list.reduce(0) { $0 + $1.count })
        return VStack(alignment: .leading, spacing: 6) {
            GeometryReader { geo in
                let gaps = CGFloat(max(0, list.count - 1)) * 1.5
                HStack(spacing: 1.5) {
                    ForEach(list) { s in
                        let dim = filter.coverage != nil && filter.coverage != s.state
                        RoundedRectangle(cornerRadius: 2)
                            .fill(tint(s.state).opacity(dim ? 0.18 : 0.85))
                            .frame(width: max(2, (geo.size.width - gaps) * CGFloat(s.count) / CGFloat(total)))
                            .onTapGesture { toggle(s.state) }
                            .help("\(plural(s.count, "package")) · \(s.state.title)")
                    }
                }
            }
            .frame(height: 10)
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(list) { s in
                        let on = filter.coverage == s.state
                        Button { toggle(s.state) } label: {
                            HStack(spacing: 5) {
                                Circle().fill(tint(s.state)).frame(width: 7, height: 7)
                                Text("\(s.state.title) \(s.count)").font(.system(size: 11, weight: on ? .semibold : .regular)).monospacedDigit()
                                    .foregroundStyle(on ? Color.primary : Color.secondary)
                            }
                            .padding(.horizontal, 7).padding(.vertical, 2)
                            .background(Capsule().fill(on ? tint(s.state).opacity(0.14) : Color.clear))
                            .overlay(Capsule().stroke(on ? tint(s.state).opacity(0.35) : Color.clear))
                            .contentShape(Capsule())
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.vertical, 1)
            }
            .frame(height: 24)
        }
    }

    func toggle(_ s: PackageCoverage.State) {
        withAnimation(.snappy(duration: 0.2)) { filter.coverage = filter.coverage == s ? nil : s }
    }

    /// A card per kind, in a row of fixed height. Not a LazyVGrid (a lazy grid outside a
    /// scroll view has no bounded height to work against) and not a wrapping layout (whose
    /// height depends on the width it is asked about, and SwiftUI asks with zero). Either
    /// one out-argues the table below and pushes the page off the top of the window.
    func kindGrid(_ kinds: [KindTally]) -> some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(kinds) { k in
                    KindCard(tally: k, selected: filter.kind == k.kind) {
                        withAnimation(.snappy(duration: 0.2)) { filter.kind = filter.kind == k.kind ? nil : k.kind }
                    }
                    .frame(width: 176, height: 62)
                }
            }
            .padding(.vertical, 1)
        }
        .frame(height: 64)
    }

    /// The three questions worth asking of an inventory that has nothing wrong with it yet.
    func worries(_ tally: Tally) -> some View {
        HStack(spacing: 8) {
            worry("arrow.down.circle", "\(tally.outdated) update ready", .blue, tally.outdated, filter.outdated) { filter.outdated.toggle() }
            worry("trash.slash", "\(tally.unmaintained) unmaintained", .brown, tally.unmaintained, filter.unmaintained) { filter.unmaintained.toggle() }
            worry("exclamationmark.triangle", "\(tally.vulnerable) with advisories", .red, tally.vulnerable, filter.vulnerable) { filter.vulnerable.toggle() }
            Spacer(minLength: 0)
        }
        .frame(height: 24)
    }

    func worry(_ symbol: String, _ text: String, _ tint: Color, _ count: Int, _ on: Bool, _ action: @escaping () -> Void) -> some View {
        Button { withAnimation(.snappy(duration: 0.2)) { action() } } label: {
            HStack(spacing: 5) {
                Image(systemName: symbol).font(.system(size: 10.5))
                Text(text).font(.system(size: 11.5, weight: on ? .semibold : .regular)).monospacedDigit()
            }
            .foregroundStyle(count == 0 ? AnyShapeStyle(.tertiary) : AnyShapeStyle(tint))
            .padding(.horizontal, 9).padding(.vertical, 3)
            .background(Capsule().fill(tint.opacity(on ? 0.16 : 0.07)))
            .overlay(Capsule().stroke(on ? tint.opacity(0.4) : Color.clear))
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .disabled(count == 0)
    }
}

/// One kind of software: the count, a coverage bar, and what is wrong inside it.
struct KindCard: View {
    var tally: InventoryOverview.KindTally
    var selected: Bool
    var action: () -> Void
    @State private var hover = false

    var body: some View {
        let share = Double(tally.checked) / Double(max(1, tally.total))
        Button(action: action) {
            VStack(alignment: .leading, spacing: 5) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(tally.kind.title).font(.system(size: 11.5, weight: .medium)).lineLimit(1).truncationMode(.tail)
                    Spacer(minLength: 2)
                    Text(tally.total.formatted()).font(.system(size: 13, weight: .semibold)).monospacedDigit()
                }
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        Capsule().fill(Color.orange.opacity(0.22))
                        Capsule().fill(Color.blue.opacity(0.65)).frame(width: geo.size.width * share)
                    }
                }
                .frame(height: 5)
                HStack(spacing: 6) {
                    Text("\(Int((share * 100).rounded()))% checked").font(.system(size: 10.5)).foregroundStyle(.secondary)
                    Spacer(minLength: 2)
                    if tally.vulnerable > 0 {
                        Label("\(tally.vulnerable)", systemImage: "exclamationmark.triangle.fill")
                            .font(.system(size: 10)).foregroundStyle(.red)
                    }
                    if tally.outdated > 0 {
                        Label("\(tally.outdated)", systemImage: "arrow.down.circle")
                            .font(.system(size: 10)).foregroundStyle(.blue)
                    }
                }
            }
            .padding(.horizontal, 10).padding(.vertical, 8)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(RoundedRectangle(cornerRadius: 9).fill(Color(nsColor: .textBackgroundColor)))
            .overlay(RoundedRectangle(cornerRadius: 9).stroke(selected ? Page.inventory.tint.opacity(0.75) : Color.primary.opacity(hover ? 0.18 : 0.07), lineWidth: selected ? 1.5 : 1))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
        .help("\(plural(tally.total, "package")) · \(tally.checked) matched against a source")
    }
}
