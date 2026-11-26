import AppKit
import Foundation
import HeimdallCore
import UserNotifications

/// UserDefaults keys shared by Settings (@AppStorage) and the model.
enum SettingsKey {
    static let checkForUpdates = "checkForUpdates"
}

// MARK: - Notifications

/// Posts one notification per scan when something exploited appeared that wasn't there before.
/// Only a bundled .app has an identity the notification center accepts; under `swift run`
/// this is a no-op rather than a crash.
enum Notifier {
    static let enabledKey = "notifyExploited"
    static var available: Bool { Bundle.main.bundleIdentifier != nil && Bundle.main.bundleURL.pathExtension == "app" }
    static var enabled: Bool { UserDefaults.standard.object(forKey: enabledKey) as? Bool ?? true }

    /// Ask once, from the app (never from the background job, which has no one to ask).
    static func requestAuthorization() async {
        guard available else { return }
        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])
    }

    static func post(_ items: [Alerts.Item], mayAsk: Bool) async {
        guard available, enabled, let m = Alerts.message(items) else { return }
        let center = UNUserNotificationCenter.current()
        var status = await center.notificationSettings().authorizationStatus
        if status == .notDetermined, mayAsk {
            await requestAuthorization()
            status = await center.notificationSettings().authorizationStatus
        }
        guard status == .authorized || status == .provisional else { return }
        let c = UNMutableNotificationContent()
        c.title = m.title
        c.body = m.body
        c.sound = .default
        c.threadIdentifier = "exploited"
        try? await center.add(UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil))
    }
}

// MARK: - The LaunchAgent

/// A per-user LaunchAgent that runs this app's own binary with `--background-scan` on the
/// auto-scan interval, so scans (and their notifications) happen while the window is closed.
/// It lives in ~/Library/LaunchAgents and is loaded with launchctl into the gui/<uid> domain:
/// no root, no helper, and it disappears when switched off.
enum BackgroundAgent {
    static let label = "com.rgregory.heimdall.scan"
    static var plistURL: URL { Paths.home.appendingPathComponent("Library/LaunchAgents/\(label).plist") }
    static var installed: Bool { FileManager.default.fileExists(atPath: plistURL.path) }
    /// Only a built .app has a stable executable path worth pointing launchd at.
    static var available: Bool { Bundle.main.bundleURL.pathExtension == "app" }
    private static var domain: String { "gui/\(getuid())" }

    static func plist(executable: String, hours: Int) -> [String: Any] {
        [
            "Label": label,
            "ProgramArguments": [executable, "--background-scan"],
            "StartInterval": max(1, hours) * 3600,
            "RunAtLoad": false,
            "ProcessType": "Background",
            "LowPriorityIO": true,
            "Nice": 10,
            "StandardOutPath": "/dev/null",
            "StandardErrorPath": Paths.support.appendingPathComponent("background.log").path,
        ]
    }

    /// Write and (re)load the agent. Returns an error message, or nil on success.
    @discardableResult
    static func install(hours: Int) async -> String? {
        guard available, let exe = Bundle.main.executableURL?.path else { return "Background scans need the built Heimdall.app." }
        guard hours > 0 else { return await uninstall() }
        do {
            let data = try PropertyListSerialization.data(fromPropertyList: plist(executable: exe, hours: hours), format: .xml, options: 0)
            Paths.ensure(plistURL.deletingLastPathComponent())
            try data.write(to: plistURL, options: .atomic)
        } catch { return "Couldn't write \(plistURL.path): \(error.localizedDescription)" }
        guard let launchctl = Shell.systemTool("launchctl") else { return "launchctl not found." }
        _ = await Shell.run(launchctl, ["bootout", "\(domain)/\(label)"], timeout: 15)
        let r = await Shell.run(launchctl, ["bootstrap", domain, plistURL.path], timeout: 15)
        return r.ok ? nil : "launchctl bootstrap failed: \(r.stderr.trimmingCharacters(in: .whitespacesAndNewlines))"
    }

    @discardableResult
    static func uninstall() async -> String? {
        if let launchctl = Shell.systemTool("launchctl") {
            _ = await Shell.run(launchctl, ["bootout", "\(domain)/\(label)"], timeout: 15)
        }
        guard installed else { return nil }
        do { try FileManager.default.removeItem(at: plistURL) } catch { return "Couldn't remove \(plistURL.path): \(error.localizedDescription)" }
        return nil
    }

    /// The app was moved or the interval changed since the agent was written: rewrite it.
    static func refreshIfNeeded(hours: Int) async {
        guard installed, available, let exe = Bundle.main.executableURL?.path else { return }
        let current = (try? Data(contentsOf: plistURL)).flatMap { try? PropertyListSerialization.propertyList(from: $0, format: nil) as? [String: Any] }
        let args = current?["ProgramArguments"] as? [String]
        let interval = current?["StartInterval"] as? Int
        if args?.first != exe || interval != max(1, hours) * 3600 { await install(hours: hours) }
    }
}

// MARK: - Headless run

/// What the LaunchAgent runs: the same scan the window does, saved where the window reads it,
/// followed by a notification if something exploited is new. Skips itself while the app is
/// open (its own scheduler is in charge) or when a scan is recent enough.
@MainActor
enum BackgroundScan {
    static func run() -> Never {
        let me = ProcessInfo.processInfo.processIdentifier
        let others = NSRunningApplication.runningApplications(withBundleIdentifier: Bundle.main.bundleIdentifier ?? Shell.defaultsSuite)
        if others.contains(where: { $0.processIdentifier != me }) { exit(0) }
        Task.detached(priority: .background) {
            await scan()
            exit(0)
        }
        dispatchMain()
    }

    nonisolated static func scan() async {
        let d = UserDefaults.standard
        let stored = d.integer(forKey: "autoScanHours")
        let hours = stored == 0 ? 12 : stored
        guard hours > 0 else { return }
        let before = ReportStore.latest()
        // launchd's interval counts from its own last run; the app may have scanned since.
        if let b = before, !b.partial, Date().timeIntervalSince(b.generated) < Double(hours) * 3600 * 0.8 { return }

        let options = d.data(forKey: "scanOptions").flatMap { try? JSONDecoder().decode(ScanOptions.self, from: $0) } ?? ScanOptions()
        // Never prompt from the background: a keychain dialog with no window behind it is worse
        // than a slower, keyless NVD run.
        let nvd = d.bool(forKey: "secrets.nvd") ? Keychain.get(account: "nvd-api-key", interactive: false) : nil
        let vc = d.bool(forKey: "secrets.vulncheck") ? Keychain.get(account: "vulncheck-token", interactive: false) : nil
        CacheMaintenance.sweep()
        let report = await Scanner(options: options, nvdAPIKey: nvd, vulnCheckToken: vc).run { _, _ in }
        ReportStore.save(report)

        let exceptions = d.data(forKey: "findingExceptions").flatMap { try? JSONDecoder().decode([FindingException].self, from: $0) } ?? []
        await Notifier.post(Alerts.newExploited(current: report, previous: before, exceptions: exceptions), mayAsk: false)
    }
}

