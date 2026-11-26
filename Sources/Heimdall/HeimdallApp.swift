import AppKit
import HeimdallCore
import SwiftUI

/// One binary, two jobs: the app, or (from the LaunchAgent) a headless scan that exits.
@main
@MainActor
enum Entry {
    static func main() {
        if CommandLine.arguments.contains("--background-scan") { BackgroundScan.run() }
        HeimdallApp.main()
    }
}

struct HeimdallApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @State private var model = AppModel()
    @AppStorage("menuBarEnabled") private var menuBarEnabled = true

    var body: some Scene {
        WindowGroup("Heimdall", id: "main") {
            ContentView()
                .environment(model)
                .frame(minWidth: 960, minHeight: 680)
        }
        .defaultSize(width: 1240, height: 900)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Scan") {
                Button("Scan Now") { model.scan() }
                    .keyboardShortcut("r", modifiers: .command)
                    .disabled(model.scanning)
                Divider()
                Button("Export Report as JSON…") { model.export(.json) }
                    .keyboardShortcut("e", modifiers: [.command, .shift])
                    .disabled(model.report == nil)
                Button("Export Findings as CSV…") { model.export(.csv) }
                    .disabled(model.report == nil)
                Button("Export SBOM as CycloneDX…") { model.export(.cycloneDX) }
                    .disabled(model.report == nil)
            }
            CommandGroup(after: .sidebar) {
                // ⌘1–⌘9 for the first nine pages; any beyond that get no shortcut ("10" isn't a key).
                ForEach(Array(Page.allCases.enumerated()), id: \.element) { i, p in
                    if i < 9 {
                        Button(p.title) { model.page = p }
                            .keyboardShortcut(KeyEquivalent(Character(String(i + 1))), modifiers: .command)
                    } else {
                        Button(p.title) { model.page = p }
                    }
                }
            }
        }

        // The menu bar item. Turning it off is blocked while the Dock icon is hidden (Settings ▸ Display).
        MenuBarExtra(isInserted: $menuBarEnabled) {
            MenuBarPanel().environment(model)
        } label: {
            MenuBarLabel().environment(model)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView().environment(model)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ n: Notification) {
        // Launched from `swift run` there is no bundle, so the policy is set explicitly either way:
        // .regular normally, .accessory when the Dock icon is hidden.
        Presentation.apply()
        if let icon = Icons.normal { NSApp.applicationIconImage = icon }
        if Presentation.dockIconHidden {
            // A menu bar app shouldn't throw its window up at login; the panel opens it.
            Task { @MainActor in
                for w in NSApp.windows where w.isVisible && w.styleMask.contains(.titled) { w.close() }
            }
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    /// With the Dock icon hidden, closing the window leaves Heimdall running in the menu bar.
    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool {
        !Presentation.dockIconHidden
    }
}
