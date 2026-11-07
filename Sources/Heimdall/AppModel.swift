import AppKit
import Foundation
import HeimdallCore
import Observation
import Security
import SwiftUI
import UniformTypeIdentifiers

enum Page: String, CaseIterable, Identifiable, Hashable {
    case front, exploited, system, apps, homebrew, languages, ledger, inventory, sources
    var id: String { rawValue }
    var title: String {
        switch self {
        case .front: return "Brief"
        case .exploited: return "Exploited"
        case .system: return "macOS"
        case .apps: return "Apps"
        case .homebrew: return "Homebrew"
        case .languages: return "Languages"
        case .ledger: return "Advisories"
        case .inventory: return "Inventory"
        case .sources: return "Sources"
        }
    }
    var symbol: String {
        switch self {
        case .front: return "eye"
        case .exploited: return "flame"
        case .system: return "desktopcomputer"
        case .apps: return "square.grid.2x2"
        case .homebrew: return "mug"
        case .languages: return "chevron.left.forwardslash.chevron.right"
        case .ledger: return "list.bullet.rectangle"
        case .inventory: return "shippingbox"
        case .sources: return "antenna.radiowaves.left.and.right"
        }
    }
    var desk: Desk? {
        switch self {
        case .system: return .system
        case .apps: return .apps
        case .homebrew: return .homebrew
        case .languages: return .languages
        default: return nil
        }
    }
    /// Things-style accent for the page's sidebar icon.
    var tint: Color {
        switch self {
        case .front: return .blue
        case .exploited: return .red
        case .system: return .gray
        case .apps: return .indigo
        case .homebrew: return .orange
        case .languages: return .purple
        case .ledger: return .teal
        case .inventory: return .brown
        case .sources: return .green
        }
    }
}

@MainActor
@Observable
final class AppModel {
    var report: ScanReport?
    var previous: ScanReport?
    var scanning = false
    var stage = ""
    var progress = 0.0
    var page: Page = .front
    var search = ""
    var selectedVuln: VulnSelection?
    var lastError: String?

    // Persisted by persist() — called from Settings' onChange and after mute changes.
    var options: ScanOptions
    var muted: Set<String>
    var nvdAPIKey: String
    var vulnCheckToken: String

    private var scheduler: Task<Void, Never>?

    init() {
        if let d = UserDefaults.standard.data(forKey: "scanOptions"), let o = try? JSONDecoder().decode(ScanOptions.self, from: d) { options = o }
        else { options = ScanOptions() }
        muted = Set(UserDefaults.standard.stringArray(forKey: "muted") ?? [])
        nvdAPIKey = Keychain.get(account: "nvd-api-key") ?? ""
        vulnCheckToken = Keychain.get(account: "vulncheck-token") ?? ""
        report = ReportStore.latest()
        previous = ReportStore.previous()
        updateBadge()
        startScheduler()
    }

    func persistOptions() {
        if let d = try? JSONEncoder().encode(options) { UserDefaults.standard.set(d, forKey: "scanOptions") }
    }
    func persistMuted() { UserDefaults.standard.set(Array(muted), forKey: "muted"); updateBadge() }
    func persistKey() { Keychain.set(nvdAPIKey, account: "nvd-api-key") }
    func persistVulnCheck() { Keychain.set(vulnCheckToken, account: "vulncheck-token") }

    var autoScanHours: Int {
        get { let v = UserDefaults.standard.integer(forKey: "autoScanHours"); return v == 0 ? 12 : v }
        set { UserDefaults.standard.set(newValue, forKey: "autoScanHours"); startScheduler() }
    }

    func startScheduler() {
        scheduler?.cancel()
        scheduler = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                let hours = self.autoScanHours
                if hours > 0 {
                    let age = self.report.map { Date().timeIntervalSince($0.generated) } ?? .infinity
                    if age > Double(hours) * 3600, !self.scanning { self.scan() }
                }
                try? await Task.sleep(nanoseconds: 15 * 60 * 1_000_000_000)
            }
        }
    }

    // MARK: scanning

    func scan() {
        guard !scanning else { return }
        scanning = true; stage = "Starting"; progress = 0; lastError = nil
        let before = report?.partial == true ? previous : report
        let scanner = Scanner(options: options, nvdAPIKey: nvdAPIKey.isEmpty ? nil : nvdAPIKey,
                              vulnCheckToken: vulnCheckToken.isEmpty ? nil : vulnCheckToken)
        let model = self   // @MainActor class: safe to hand to other tasks; lives as long as the app
        Task.detached(priority: .userInitiated) {
            let r = await scanner.run(progress: { stage, fraction in
                Task { @MainActor in model.stage = stage; model.progress = fraction }
            }, partial: { interim in
                Task { @MainActor in
                    guard model.scanning else { return }
                    model.report = interim
                    model.updateBadge()
                }
            })
            ReportStore.save(r)
            await MainActor.run {
                model.previous = before
                model.report = r
                model.scanning = false
                model.updateBadge()
            }
        }
    }

    // MARK: muting

    static func muteKey(_ f: Finding, _ v: Vulnerability) -> String { "v|\(f.package.ecosystem.rawValue)|\(f.package.name)|\(v.headlineID)" }
    static func muteKey(_ p: Package) -> String { "p|\(p.ecosystem.rawValue)|\(p.name)" }

    func isMuted(_ f: Finding, _ v: Vulnerability) -> Bool { muted.contains(Self.muteKey(f, v)) || muted.contains(Self.muteKey(f.package)) }
    func toggleMute(_ f: Finding, _ v: Vulnerability) { let k = Self.muteKey(f, v); if muted.contains(k) { muted.remove(k) } else { muted.insert(k) }; persistMuted() }
    func toggleMute(_ p: Package) { let k = Self.muteKey(p); if muted.contains(k) { muted.remove(k) } else { muted.insert(k) }; persistMuted() }

    /// The report with ignored packages/vulnerabilities taken out.
    var visible: ScanReport? {
        guard var r = report else { return nil }
        r.findings = r.findings.compactMap { f in
            var f = f
            f.vulns = f.vulns.filter { !isMuted(f, $0) }
            return f.vulns.isEmpty ? nil : f
        }
        return r
    }

    var changes: Changes? { visible.map { Changes(current: $0, previous: previous) } }

    /// Findings for a page, filtered by the toolbar search.
    func findings(for page: Page) -> [Finding] {
        guard let r = visible else { return [] }
        var list: [Finding]
        switch page {
        case .exploited: list = r.kevFindings.map { f in var f = f; f.vulns = f.vulns.filter(\.isKEV); return f }
        default: list = page.desk.map { r.findings(in: $0) } ?? r.findings
        }
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        if !q.isEmpty {
            list = list.compactMap { f in
                let p = f.package
                if [p.name, p.parent ?? "", p.bundleID ?? "", p.cask ?? "", p.browser ?? ""].contains(where: { $0.lowercased().contains(q) }) { return f }
                var f = f
                f.vulns = f.vulns.filter { v in ([v.id] + v.aliases).contains { $0.lowercased().contains(q) } || v.summary.lowercased().contains(q) }
                return f.vulns.isEmpty ? nil : f
            }
        }
        return list
    }

    /// Dock badge with the exploited count, and the icon turns red while anything exploited
    /// (or a malicious extension) is present. Back to normal once it's fixed or ignored.
    func updateBadge() {
        let n = visible?.kevCount ?? 0
        guard let app = NSApp else { return }
        app.dockTile.badgeLabel = n > 0 ? "\(n)" : nil
        app.applicationIconImage = n > 0 ? Icons.alert : Icons.normal
    }

    // MARK: export

    func export(csv: Bool) {
        guard let r = visible else { return }
        let panel = NSSavePanel()
        let day = r.generated.formatted(.iso8601.year().month().day())
        panel.nameFieldStringValue = "heimdall-\(r.posture.hostName)-\(day).\(csv ? "csv" : "json")"
        panel.allowedContentTypes = [csv ? .commaSeparatedText : .json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            if csv { try ReportExport.csv(r).write(to: url, atomically: true, encoding: .utf8) }
            else { try ReportExport.json(r).write(to: url, options: .atomic) }
        } catch { lastError = "Export failed: \(error.localizedDescription)" }
    }

    func clearCache() {
        try? FileManager.default.removeItem(at: Paths.cache)
    }

    func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }
}

struct VulnSelection: Identifiable {
    var finding: Finding
    var vuln: Vulnerability
    var id: String { finding.id + "|" + vuln.id }
}

/// The normal and red ("something exploited is installed") app icons.
@MainActor
enum Icons {
    /// In a built .app, nil restores the bundle icon; under `swift run` there is none, so use the PNG.
    static let normal: NSImage? = Bundle.main.bundleURL.pathExtension == "app" ? nil : find("AppIcon.png")
    static let alert: NSImage? = find("AppIconAlert.png")

    static func find(_ name: String) -> NSImage? {
        if let u = Bundle.main.url(forResource: (name as NSString).deletingPathExtension, withExtension: "png"), let img = NSImage(contentsOf: u) { return img }
        var u = Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])
        for _ in 0..<6 {
            u.deleteLastPathComponent()
            if let img = NSImage(contentsOf: u.appendingPathComponent("Resources/" + name)) { return img }
        }
        return nil
    }
}

/// The NVD API key lives in the login keychain, not in preferences.
enum Keychain {
    static let service = "Heimdall"

    static func get(account: String) -> String? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }

    static func set(_ value: String, account: String) {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        SecItemDelete(q as CFDictionary)
        guard !value.isEmpty else { return }
        var add = q
        add[kSecValueData as String] = Data(value.utf8)
        SecItemAdd(add as CFDictionary, nil)
    }
}
