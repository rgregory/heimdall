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
