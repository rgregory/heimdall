import AppKit
import HeimdallCore
import SwiftUI

@main
struct HeimdallApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @State private var model = AppModel()

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
                Button("Export Report as JSON…") { model.export(csv: false) }
                    .keyboardShortcut("e", modifiers: [.command, .shift])
                    .disabled(model.report == nil)
                Button("Export Findings as CSV…") { model.export(csv: true) }
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

        Settings {
            SettingsView().environment(model)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ n: Notification) {
        // Launched from `swift run` there is no bundle; make it a regular foreground app anyway.
        NSApp.setActivationPolicy(.regular)
        if let icon = Icons.normal { NSApp.applicationIconImage = icon }
        NSApp.activate(ignoringOtherApps: true)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool { true }
}
