import AppKit
import HeimdallCore
import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        TabView {
            SourcesSettings().tabItem { Label("Sources", systemImage: "tray.full") }
            MatchingSettings().tabItem { Label("Matching", systemImage: "link") }
            NewsSettings().tabItem { Label("News", systemImage: "newspaper") }
            DisplaySettings().tabItem { Label("Display", systemImage: "paintbrush") }
        }
        .frame(width: 560, height: 470)
        .onChange(of: model.options) { _, _ in model.persistOptions() }
        .onChange(of: model.nvdAPIKey) { _, _ in model.persistKey() }
        .onChange(of: model.vulnCheckToken) { _, _ in model.persistVulnCheck() }
    }
}

struct SourcesSettings: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        @Bindable var model = model
        Form {
            Section("Installed software") {
                Toggle("Applications (/Applications, ~/Applications)", isOn: $model.options.apps)
                Toggle("Homebrew formulae and casks", isOn: $model.options.homebrew)
                Toggle("Use `brew vulns` when this Homebrew has it", isOn: $model.options.useBrewVulns).disabled(!model.options.homebrew)
                Toggle("Python (site-packages, pipx, uv, pyenv, conda)", isOn: $model.options.languages.python)
                Toggle("npm global packages", isOn: $model.options.languages.npm)
                Toggle("…including their dependencies", isOn: $model.options.languages.npmNested).disabled(!model.options.languages.npm).padding(.leading, 16)
                Toggle("cargo install", isOn: $model.options.languages.cargo)
                Toggle("Ruby gems", isOn: $model.options.languages.gems)
                Toggle("Go binaries in ~/go/bin", isOn: $model.options.languages.go)
                Toggle("…and Go programs in Homebrew's bin", isOn: $model.options.languages.goInHomebrew).disabled(!model.options.languages.go).padding(.leading, 16)
                Toggle("Browser extensions (Chrome, Brave, Edge, Vivaldi, Arc, Opera, Firefox)", isOn: $model.options.extensions)
            }
            Section {
                PathList(title: "Extra virtualenvs or site-packages", paths: $model.options.languages.extraPythonRoots)
                PathList(title: "Extra folders of Go binaries", paths: $model.options.languages.extraGoRoots)
                PathList(title: "Extra application folders", paths: $model.options.extraAppRoots)
            } header: { Text("Extra locations") } footer: {
                Text("Only folders your account can read. Nothing here needs an administrator password.").foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}

struct PathList: View {
    var title: String
    @Binding var paths: [String]
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(title)
                Spacer()
                Button("Add…") {
                    let p = NSOpenPanel(); p.canChooseDirectories = true; p.canChooseFiles = false; p.allowsMultipleSelection = true
                    if p.runModal() == .OK { paths = (paths + p.urls.map(\.path)).uniqued() }
                }
            }
            ForEach(paths, id: \.self) { path in
                HStack {
                    Text(path).font(.system(.caption, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Button { paths.removeAll { $0 == path } } label: { Image(systemName: "minus.circle") }.buttonStyle(.borderless)
                }
            }
        }
    }
}

struct MatchingSettings: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        @Bindable var model = model
        Form {
            Section {
                Toggle("Look up apps, macOS and Safari in NVD", isOn: $model.options.nvd)
                SecureField("NVD API key (optional)", text: $model.nvdAPIKey)
                Link("Request a free NVD API key", destination: URL(string: "https://nvd.nist.gov/developers/request-an-api-key")!)
                Toggle("Keep NVD matches that have no version bounds", isOn: $model.options.includeUnbounded)
            } header: { Text("NVD") } footer: {
                Text("Without a key NVD allows 5 requests per 30 seconds, so the first scan of many apps takes a few minutes; answers are cached for a day. The key is stored in your login keychain.").foregroundStyle(.secondary)
            }
            Section {
                Toggle("Vendor advisories: Apple notes, Chrome Releases, Mozilla, Microsoft", isOn: $model.options.vendorFeeds)
                Toggle("Score unrated advisories from CVE records and CISA Vulnrichment", isOn: $model.options.cveRecords)
                Toggle("Exploited lists (EUVD, VulnCheck) and public exploits (Exploit-DB, Metasploit, nuclei)", isOn: $model.options.exploitSignals)
                SecureField("VulnCheck API token (optional)", text: $model.vulnCheckToken)
                Toggle("Check for newer app versions (Sparkle, App Store, Homebrew casks)", isOn: $model.options.updateChecks)
                Toggle("Fetch EPSS exploit-probability scores", isOn: $model.options.epss)
            } header: { Text("More sources") } footer: {
                Text("A free VulnCheck token (vulncheck.com) adds their exploited list. Your ~/nuclei-templates checkout is used when present.").foregroundStyle(.secondary)
            }
            Section {
                Toggle("Offline: use cached feeds only", isOn: $model.options.offline)
                HStack {
                    Button("Clear cached feeds") { model.clearCache() }
                    Button("Edit app → CPE mappings…") {
                        let u = Paths.support.appendingPathComponent("app-cpe.json")
                        if !FileManager.default.fileExists(atPath: u.path) {
                            try? Data("[\n  { \"bundleID\": \"com.example.App\", \"cpe\": [\"example:app\"] }\n]\n".utf8).write(to: u)
                        }
                        NSWorkspace.shared.open(u)
                    }
                }
            } header: { Text("Network") } footer: {
                Text("Mappings tell Heimdall which NVD product an app is (vendor:product). Your entries take priority over the built-in list.").foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}

struct DisplaySettings: View {
    @Environment(AppModel.self) private var model
    @AppStorage("appearance") private var appearance = "system"
    @State private var hours = 12

    var body: some View {
        @Bindable var model = model
        Form {
            Picker("Appearance", selection: $appearance) {
                Text("Follow the system").tag("system")
                Text("Light").tag("light")
                Text("Dark").tag("dark")
            }
            Picker("Scan automatically", selection: $hours) {
                Text("Never").tag(-1)
                Text("Every 6 hours").tag(6)
                Text("Every 12 hours").tag(12)
                Text("Every day").tag(24)
            }
            .onChange(of: hours) { _, h in model.autoScanHours = h }
            Section {
                Text("\(model.muted.count) ignored item(s)")
                Button("Stop ignoring everything") { model.muted = []; model.persistMuted() }.disabled(model.muted.isEmpty)
            }
        }
        .formStyle(.grouped)
        .onAppear { hours = model.autoScanHours }
    }
}

struct NewsSettings: View {
    @Environment(AppModel.self) private var model
    @State private var name = ""
    @State private var url = ""

    var body: some View {
        @Bindable var model = model
        Form {
            Section {
                Toggle("Fetch security news and match it to this Mac", isOn: $model.options.news)
            } footer: {
                Text("Feeds are fetched at most hourly. Stories are matched by CVE ID and by the names of installed apps and Homebrew packages.").foregroundStyle(.secondary)
            }
            Section("Feeds") {
                ForEach(model.options.newsFeeds, id: \.url) { f in
                    HStack {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(f.name)
                            Text(f.url).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                        }
                        Spacer()
                        Button { model.options.newsFeeds.removeAll { $0.url == f.url } } label: { Image(systemName: "minus.circle") }.buttonStyle(.borderless)
                    }
                }
                HStack {
                    TextField("Name", text: $name).frame(width: 140)
                    TextField("https://…/feed", text: $url)
                    Button("Add") {
                        let u = url.trimmingCharacters(in: .whitespaces)
                        guard u.hasPrefix("https://") || u.hasPrefix("http://") else { return }
                        model.options.newsFeeds.append(NewsFeed(name: name.isEmpty ? (URL(string: u)?.host ?? u) : name, url: u))
                        name = ""; url = ""
                    }
                    .disabled(url.isEmpty)
                }
                Button("Restore default feeds") { model.options.newsFeeds = NewsFeed.defaults }
            }
        }
        .formStyle(.grouped)
        .disabled(false)
    }
}
