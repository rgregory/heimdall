import AppKit
import HeimdallCore
import SwiftUI

// MARK: - Shared

extension Severity {
    /// Things-style colour.
    var tint: Color {
        switch self {
        case .critical: return Color(red: 0.75, green: 0.1, blue: 0.12)
        case .high: return .red
        case .medium: return .orange
        case .low: return .yellow
        case .none, .unknown: return .gray
        }
    }
}

extension Int {
    var spelled: String {
        let w = ["No", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten"]
        return self >= 0 && self < w.count ? w[self] : formatted()
    }
}

func plural(_ n: Int, _ one: String, _ many: String? = nil) -> String { "\(n.formatted()) \(n == 1 ? one : (many ?? one + "s"))" }

extension Date {
    var shortDay: String { formatted(.dateTime.month(.abbreviated).day().year()) }
    var relative: String { formatted(.relative(presentation: .named)) }
}

/// Fix hints are sometimes "command  — note"; the copyable part is before the dash.
func commandPart(_ hint: String) -> String { hint.components(separatedBy: "  — ").first ?? hint }
func isCommand(_ hint: String) -> Bool { ["brew ", "pip", "python3 ", "npm ", "cargo ", "gem ", "uv ", "go "].contains { hint.hasPrefix($0) } }

func firstFix(_ v: Vulnerability, above version: String) -> String {
    let above = v.fixed.filter { !$0.hasPrefix("commit") && Version.compare($0, version) > 0 }
    return above.min(by: { Version.less($0, $1) }) ?? (v.fixed.first ?? "—")
}

// MARK: - Palette

/// Warm paper behind the content, carried over from Argus.
enum Ink {
    static let paper2 = Color.dyn(0xfaf7f0, 0x1d1c22)
}

extension Color {
    static func dyn(_ light: UInt32, _ dark: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { ap in
            let hex = ap.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
            return NSColor(srgbRed: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255, blue: CGFloat(hex & 0xff) / 255, alpha: 1)
        })
    }
}

// MARK: - Things theme

/// Things' to-do circle, used for severity: ring for advisories, filled for exploited.
struct SeverityRing: View {
    var severity: Severity
    var exploited = false
    var body: some View {
        ZStack {
            Circle().strokeBorder(severity.tint, lineWidth: 1.5)
            if exploited { Circle().fill(severity == .unknown ? .red : severity.tint).padding(3.5) }
        }
        .frame(width: 16, height: 16)
    }
}

struct ThingsTag: View {
    var text: String
    var tint: Color = .secondary
    var filled = false
    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .medium))
            .foregroundStyle(filled ? .white : tint)
            .padding(.horizontal, 7).padding(.vertical, 1.5)
            .background(Capsule().fill(filled ? AnyShapeStyle(tint) : AnyShapeStyle(tint.opacity(0.12))))
    }
}

struct ModernCommand: View {
    @Environment(AppModel.self) private var model
    var text: String
    @State private var copied = false
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "wrench.and.screwdriver").foregroundStyle(.secondary).font(.system(size: 11))
            Text(text).font(.system(size: 12, design: .monospaced)).textSelection(.enabled).lineLimit(2)
            Spacer(minLength: 4)
            if isCommand(text) {
                Button(copied ? "Copied" : "Copy") {
                    model.copy(commandPart(text)); copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) { copied = false }
                }
                .buttonStyle(.borderless).font(.system(size: 12, weight: .medium))
            }
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
        .background(RoundedRectangle(cornerRadius: 7).fill(Color.primary.opacity(0.05)))
    }
}
