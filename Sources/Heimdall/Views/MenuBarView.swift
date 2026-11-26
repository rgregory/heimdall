import AppKit
import HeimdallCore
import SwiftUI

// MARK: - Dock icon

/// Runtime control of the Dock icon. Heimdall is a regular app unless the Dock icon is hidden,
/// which is only honoured while the menu bar item is there to replace it — otherwise the app
/// would be running with no way to reach it.
@MainActor
enum Presentation {
    static var menuBarEnabled: Bool { UserDefaults.standard.object(forKey: "menuBarEnabled") as? Bool ?? true }
    static var dockIconHidden: Bool { UserDefaults.standard.bool(forKey: "hideDockIcon") && menuBarEnabled }

    /// Match the activation policy to the settings. Safe to call repeatedly; no relaunch needed.
    static func apply() {
        let want: NSApplication.ActivationPolicy = dockIconHidden ? .accessory : .regular
        guard NSApp.activationPolicy() != want else { return }
        NSApp.setActivationPolicy(want)
        // Coming back to the Dock leaves the windows behind whatever is in front.
        if want == .regular { NSApp.activate(ignoringOtherApps: true) }
    }
}

// MARK: - The glyph

/// Heimdall on Bifröst: a watching eye over the arc of the bridge.
///
/// Drawn into a template NSImage rather than built from SwiftUI shapes — a MenuBarExtra label
/// only renders Text and Image reliably, and a Shape in it silently doesn't draw. Being a
/// template, AppKit tints it for the light and dark menu bar and for the highlighted state.
@MainActor
enum Glyph {
    static let normal: NSImage = render(alert: false)
    static let alert: NSImage = render(alert: true)

    /// 18×18, top-left origin. Everything is inset far enough that a 1.5pt stroke stays inside.
    private static let size = NSSize(width: 18, height: 18)

    private static func eye() -> NSBezierPath {
        let p = NSBezierPath()
        p.move(to: NSPoint(x: 1.2, y: 6))
        p.curve(to: NSPoint(x: 16.8, y: 6), controlPoint1: NSPoint(x: 4.7, y: 0.8), controlPoint2: NSPoint(x: 13.3, y: 0.8))
        p.curve(to: NSPoint(x: 1.2, y: 6), controlPoint1: NSPoint(x: 13.3, y: 11.2), controlPoint2: NSPoint(x: 4.7, y: 11.2))
        p.close()
        return p
    }

    private static func slit() -> NSBezierPath { NSBezierPath(ovalIn: NSRect(x: 7.7, y: 3.4, width: 2.6, height: 5.2)) }

    /// The arch, as the cubic equivalent of a quadratic from (0.9,16.6) to (17.1,16.6)
    /// over (9,6.5) — its apex lands just below the eye.
    private static func arch() -> NSBezierPath {
        let p = NSBezierPath()
        p.move(to: NSPoint(x: 0.9, y: 16.6))
        p.curve(to: NSPoint(x: 17.1, y: 16.6), controlPoint1: NSPoint(x: 6.3, y: 9.87), controlPoint2: NSPoint(x: 11.7, y: 9.87))
        return p
    }

    private static func render(alert: Bool) -> NSImage {
        let image = NSImage(size: size, flipped: true) { _ in
            NSColor.black.setFill()
            NSColor.black.setStroke()
            if alert {
                // Solid eye with the slit knocked out.
                let solid = eye()
                solid.append(slit())
                solid.windingRule = .evenOdd
                solid.fill()
            } else {
                let outline = eye()
                outline.lineWidth = 1.5
                outline.lineJoinStyle = .round
                outline.stroke()
                slit().fill()
            }
            let bridge = arch()
            bridge.lineWidth = 1.5
            bridge.lineCapStyle = .round
            bridge.stroke()
            return true
        }
        image.isTemplate = true
        return image
    }
}

// MARK: - The menu bar item

/// The glyph in the menu bar, badged with the count while something exploited is installed.
struct MenuBarLabel: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        let n = model.visible?.kevCount ?? 0
        HStack(spacing: 3) {
            Image(nsImage: n > 0 ? Glyph.alert : Glyph.normal)
            if n > 0 { Text("\(n)").font(.system(size: 11, weight: .semibold)) }
        }
    }
}

/// The panel behind the menu bar item: status, the most urgent few findings, and the actions
/// that have to work when there is no Dock icon and no app menu.
struct MenuBarPanel: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismiss) private var dismiss

    private var report: ScanReport? { model.visible }
    private var kev: Int { report?.kevCount ?? 0 }

    private var top: [Finding] {
        guard let r = report else { return [] }
        let list = r.kevFindings.isEmpty ? r.findings.sorted { $0.priority > $1.priority } : r.kevFindings
        return Array(list.prefix(4))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            Divider()
            status
            if !top.isEmpty {
                Divider()
                VStack(alignment: .leading, spacing: 4) { ForEach(top) { row($0) } }
            }
            if let u = model.appUpdate, let url = URL(string: u.url) {
                Divider()
                Link(destination: url) {
                    Label("Heimdall \(u.version) is available", systemImage: "arrow.down.circle").font(.system(size: 12))
                }
            }
            Divider()
            footer
        }
        .padding(12)
        .frame(width: 320)
    }

    private var header: some View {
        HStack(spacing: 7) {
            Image(nsImage: Glyph.normal).foregroundStyle(.secondary)
            Text("Heimdall").font(.system(size: 13, weight: .semibold))
            Spacer()
            if let r = model.report {
                Text(r.generated.relative).font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder private var status: some View {
        if model.scanning {
            VStack(alignment: .leading, spacing: 5) {
                Text(model.stage.isEmpty ? "Scanning…" : model.stage).font(.system(size: 12))
                ProgressView(value: model.progress).controlSize(.small)
            }
        } else if let r = report {
            HStack(spacing: 8) {
                Image(systemName: kev > 0 ? "flame.fill" : "checkmark.seal")
                    .font(.system(size: 13))
                    .foregroundStyle(kev > 0 ? Color.red : Color.green)
                VStack(alignment: .leading, spacing: 1) {
                    Text(kev > 0 ? "\(plural(kev, "item")) exploited in the wild" : "Nothing exploited is installed")
                        .font(.system(size: 12.5, weight: .medium))
                    Text(summary(r)).font(.system(size: 11)).foregroundStyle(.secondary)
                }
            }
        } else {
            Text(model.loaded ? "No scan yet." : "Loading…").font(.system(size: 12)).foregroundStyle(.secondary)
        }
    }

    private func summary(_ r: ScanReport) -> String {
        var bits = [plural(r.allVulns.count, "advisory", "advisories")]
        if r.count(.critical) > 0 { bits.append("\(r.count(.critical)) critical") }
        if r.count(.high) > 0 { bits.append("\(r.count(.high)) high") }
        return bits.joined(separator: " · ")
    }

    private func row(_ f: Finding) -> some View {
        Button {
            open(f.kevCount > 0 ? .exploited : .front)
        } label: {
            HStack(spacing: 8) {
                SeverityRing(severity: f.topSeverity, exploited: f.kevCount > 0)
                VStack(alignment: .leading, spacing: 1) {
                    Text(shortModule(f.package.name)).font(.system(size: 12.5, weight: .medium)).lineLimit(1)
                    Text("\(shortVersion(f.package.version)) · \(f.vulns.first?.headlineID ?? "")")
                        .font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer(minLength: 4)
                if f.vulns.count > 1 { ThingsTag(text: "\(f.vulns.count)") }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var footer: some View {
        VStack(spacing: 1) {
            PanelButton(title: model.scanning ? "Scanning…" : "Scan Now", symbol: "arrow.clockwise", disabled: model.scanning) { model.scan() }
            PanelButton(title: "Open Heimdall", symbol: "macwindow") { open() }
            PanelButton(title: "Settings…", symbol: "gearshape") { openSettings() }
            PanelButton(title: "Quit Heimdall", symbol: "power") { NSApp.terminate(nil) }
                .keyboardShortcut("q", modifiers: .command)
        }
    }

    /// Bring up the main window — it may not exist at all when the Dock icon is hidden.
    private func open(_ page: Page? = nil) {
        if let page { model.page = page }
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
        dismiss()
    }

    private func openSettings() {
        NSApp.activate(ignoringOtherApps: true)
        if !NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil) {
            NSApp.sendAction(Selector(("showPreferencesWindow:")), to: nil, from: nil)
        }
        dismiss()
    }
}

/// A menu-like row in the panel: the panel is a window, so these are not real menu items.
struct PanelButton: View {
    var title: String
    var symbol: String
    var disabled = false
    var action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: symbol).font(.system(size: 11)).frame(width: 14)
                Text(title).font(.system(size: 12.5))
                Spacer()
            }
            .padding(.horizontal, 6).padding(.vertical, 5)
            .background(RoundedRectangle(cornerRadius: 6).fill(hovering && !disabled ? Color.primary.opacity(0.07) : Color.clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(disabled)
        .opacity(disabled ? 0.5 : 1)
        .onHover { hovering = $0 }
    }
}
