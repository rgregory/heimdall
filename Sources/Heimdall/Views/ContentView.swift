import HeimdallCore
import SwiftUI

struct ContentView: View {
    @Environment(AppModel.self) private var model
    @AppStorage("appearance") private var appearance = "system"

    var body: some View {
        @Bindable var model = model
        ModernShell()
        .sheet(item: $model.selectedVuln) { sel in
            VulnDetail(selection: sel).environment(model)
        }
        .preferredColorScheme(scheme)
        .onAppear { if model.report == nil && !model.scanning { model.scan() } }
    }

    var scheme: ColorScheme? {
        switch appearance { case "light": return .light; case "dark": return .dark; default: return nil }
    }
}

/// Findings for a page after the page's own filters.
func filtered(_ list: [Finding], minSeverity: Severity, kevOnly: Bool) -> [Finding] {
    list.compactMap { f in
        var f = f
        f.vulns = f.vulns.filter { $0.severity >= minSeverity && (!kevOnly || $0.isKEV) }
        return f.vulns.isEmpty ? nil : f
    }
}

func pageSubtitle(_ page: Page) -> String {
    switch page {
    case .front: return "What Heimdall found on this Mac, most urgent first."
    case .exploited: return "CISA's known-exploited listings over time: what touches this Mac, and everything else."
    case .news: return "Security news from the last 30 days. This Mac shows stories that name software installed here."
    case .system: return "macOS and Safari against Apple's security releases, Apple's per-release notes and NVD."
    case .apps: return "Third-party apps (NVD, vendor advisories, KEV) and browser extensions (malicious-extension list)."
    case .homebrew: return "Formulae and casks, from brew vulns or OSV.dev by upstream release tag."
    case .languages: return "Python, npm, cargo, Ruby gems and Go binaries, matched exactly by OSV.dev."
    case .ledger: return "Every advisory that applies, one line each."
    case .inventory: return "Everything examined, vulnerable or not."
    case .sources: return "What Heimdall read, what it asked, and what it sent."
    }
}

let privacyText = [
    "Heimdall runs as you and reads only metadata your account can already read: Info.plist files, Homebrew's own inventory, package metadata in site-packages and node_modules, and the build info Go embeds in binaries. It never runs as root, never asks for Full Disk Access, and changes nothing.",
    "Outbound: package names and versions go to OSV.dev; product names and versions (e.g. firefox 144.0) go to NVD; CVE ids go to FIRST EPSS; the KEV catalog and Apple's release index are plain downloads. No file contents, paths or host names leave the Mac.",
]
