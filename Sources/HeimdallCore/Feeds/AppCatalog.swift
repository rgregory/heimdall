import Foundation

/// Which NVD CPE (vendor:product) describes an installed app, and which KEV vendor/product rows
/// apply to it. Extend or override with ~/Library/Application Support/Heimdall/app-cpe.json:
///
///     [{ "bundleID": "com.example.App", "cpe": ["example:app"], "kevVendor": "example", "kevProduct": "app" }]
public struct AppCPE: Codable, Sendable {
    public var bundleID: String          // exact id, or a prefix ending in "*"
    public var cpe: [String]             // "vendor:product"
    public var kevVendor: String? = nil  // case-insensitive regex on KEV vendorProject
    public var kevProduct: String? = nil // case-insensitive regex on KEV product

    public func matches(_ id: String) -> Bool {
        bundleID.hasSuffix("*") ? id.hasPrefix(String(bundleID.dropLast())) : id == bundleID
    }
}

public enum AppCatalog {
    static func e(_ id: String, _ cpe: [String], _ kv: String? = nil, _ kp: String? = nil) -> AppCPE {
        AppCPE(bundleID: id, cpe: cpe, kevVendor: kv, kevProduct: kp)
    }

    public static let builtIn: [AppCPE] = [
        // Browsers
        e("com.google.Chrome", ["google:chrome"], "^google$", "chrom"),
        e("com.google.Chrome.beta", ["google:chrome"], "^google$", "chrom"),
        e("org.mozilla.firefox", ["mozilla:firefox"], "^mozilla$", "firefox"),
        e("org.mozilla.firefoxdeveloperedition", ["mozilla:firefox"], "^mozilla$", "firefox"),
        e("org.mozilla.thunderbird", ["mozilla:thunderbird"], "^mozilla$", "thunderbird"),
        e("com.microsoft.edgemac", ["microsoft:edge_chromium", "microsoft:edge"], "^(microsoft|google)$", "edge|chromium"),
        e("com.brave.Browser", ["brave:brave"], "^google$", "chromium"),
        e("com.operasoftware.Opera", ["opera:opera_browser"], "^google$", "chromium"),
        e("com.vivaldi.Vivaldi", ["vivaldi:vivaldi"], "^google$", "chromium"),
        e("org.torproject.torbrowser", ["torproject:tor_browser"], "^mozilla$", "firefox"),
        e("com.apple.Safari", ["apple:safari"], "^apple$", "safari|webkit"),
        // Communication
        e("us.zoom.xos", ["zoom:meetings", "zoom:zoom", "zoom:workplace_desktop"], "^zoom", "."),
        e("com.microsoft.teams2", ["microsoft:teams"], "^microsoft$", "teams"),
        e("com.microsoft.teams", ["microsoft:teams"], "^microsoft$", "teams"),
        e("com.tinyspeck.slackmacgap", ["slack:slack"]),
        e("com.hnc.Discord", ["discord:discord"]),
        e("org.whispersystems.signal-desktop", ["signal:signal-desktop", "signal:signal_desktop"]),
        e("ru.keepcoder.Telegram", ["telegram:telegram"], "^telegram$", "."),
        e("org.telegram.desktop", ["telegram:telegram_desktop"], "^telegram$", "."),
        e("net.whatsapp.WhatsApp", ["whatsapp:whatsapp_desktop", "whatsapp:whatsapp"], "^(whatsapp|meta)$", "whatsapp"),
        e("com.cisco.webexmeetingsapp", ["cisco:webex_meetings"], "^cisco$", "webex"),
        e("Cisco-Systems.Spark", ["cisco:webex_app", "cisco:webex_teams"], "^cisco$", "webex"),
        // Remote access / VPN
        e("com.teamviewer.TeamViewer", ["teamviewer:teamviewer"], "^teamviewer$", "."),
        e("com.philandro.anydesk", ["anydesk:anydesk"], "^anydesk$", "."),
        e("com.citrix.receiver.nomas", ["citrix:workspace"], "^citrix$", "workspace"),
        e("com.cisco.secureclient.gui", ["cisco:secure_client"], "^cisco$", "anyconnect|secure client"),
        e("com.cisco.anyconnect.gui", ["cisco:anyconnect_secure_mobility_client"], "^cisco$", "anyconnect|secure client"),
        e("com.fortinet.FortiClient", ["fortinet:forticlient"], "^fortinet$", "forticlient"),
        e("com.paloaltonetworks.GlobalProtect.client", ["paloaltonetworks:globalprotect"], "^palo alto", "globalprotect"),
        e("org.openvpn.client.app", ["openvpn:openvpn_connect"]),
        e("io.tailscale.ipn.macos", ["tailscale:tailscale"]),
        e("io.tailscale.ipn.macsys", ["tailscale:tailscale"]),
        e("com.microsoft.rdc.macos", ["microsoft:remote_desktop"]),
        e("com.connectwise.screenconnect*", ["connectwise:screenconnect"], "^connectwise$", "screenconnect"),
        // Developer
        e("com.microsoft.VSCode", ["microsoft:visual_studio_code"], "^microsoft$", "visual studio code"),
        e("com.docker.docker", ["docker:desktop"], "^docker$", "."),
        e("com.apple.dt.Xcode", ["apple:xcode"]),
        e("org.wireshark.Wireshark", ["wireshark:wireshark"]),
        e("com.googlecode.iterm2", ["iterm2:iterm2"]),
        e("com.sublimetext.4", ["sublimehq:sublime_text"]),
        e("com.jetbrains.intellij*", ["jetbrains:intellij_idea"], "^jetbrains$", "."),
        e("com.jetbrains.pycharm*", ["jetbrains:pycharm"], "^jetbrains$", "."),
        e("com.jetbrains.WebStorm", ["jetbrains:webstorm"], "^jetbrains$", "."),
        e("com.jetbrains.goland", ["jetbrains:goland"], "^jetbrains$", "."),
        e("com.github.GitHubClient", ["github:github_desktop"]),
        e("com.postmanlabs.mac", ["postman:postman"]),
        e("com.vmware.fusion", ["vmware:fusion"], "^vmware$", "fusion"),
        e("com.parallels.desktop.console", ["parallels:parallels_desktop"], "^parallels$", "."),
        e("org.virtualbox.app.VirtualBox", ["oracle:vm_virtualbox"], "^oracle$", "virtualbox"),
        // Documents & media
        e("com.adobe.Reader", ["adobe:acrobat_reader_dc", "adobe:acrobat_reader"], "^adobe$", "acrobat|reader"),
        e("com.adobe.Acrobat.Pro", ["adobe:acrobat_dc", "adobe:acrobat"], "^adobe$", "acrobat|reader"),
        e("com.adobe.Photoshop", ["adobe:photoshop"], "^adobe$", "photoshop"),
        e("com.adobe.illustrator", ["adobe:illustrator"], "^adobe$", "illustrator"),
        e("org.libreoffice.script", ["libreoffice:libreoffice"], "^libreoffice$", "."),
        e("org.videolan.vlc", ["videolan:vlc_media_player"]),
        e("org.gimp.gimp-2.10", ["gimp:gimp"]),
        e("org.gimp.gimp", ["gimp:gimp"]),
        e("org.inkscape.Inkscape", ["inkscape:inkscape"]),
        e("org.blenderfoundation.blender", ["blender:blender"]),
        e("com.obsproject.obs-studio", ["obsproject:obs_studio"]),
        e("com.plexapp.plexmediaserver", ["plex:media_server"], "^plex$", "media server"),
        e("com.plexapp.plexmediaplayer", ["plex:media_player"]),
        e("com.spotify.client", ["spotify:spotify"]),
        // Security / passwords
        e("com.1password.1password", ["1password:1password"]),
        e("com.bitwarden.desktop", ["bitwarden:bitwarden"]),
        e("org.keepassxc.keepassxc", ["keepassxc:keepassxc"]),
        e("com.dropbox.dropbox*", ["dropbox:dropbox"]),
        e("com.getdropbox.dropbox", ["dropbox:dropbox"]),
        e("org.7-zip.7-Zip", ["7-zip:7-zip"], "^7-zip$", "."),
        e("com.rarlab.rar", ["rarlab:winrar"], "^rarlab$", "."),
    ]

    public static func load() -> [AppCPE] {
        let user = Paths.support.appendingPathComponent("app-cpe.json")
        let extra = (try? Data(contentsOf: user)).flatMap { try? JSONDecoder().decode([AppCPE].self, from: $0) } ?? []
        // User entries win.
        return extra + builtIn
    }

    public static func entry(for p: Package, in catalog: [AppCPE]) -> AppCPE? {
        guard let id = p.bundleID else { return nil }
        return catalog.first { $0.matches(id) }
    }
}

/// Apple's "Apple security releases" index (support.apple.com/100100).
public enum AppleReleases {
    public static let url = "https://support.apple.com/en-us/100100"

    public static func load(offline: Bool) async -> ([AppleRelease], SourceStatus) {
        let cache = DiskCache("feeds")
        var html = cache.data("apple-security-releases.html", maxAge: offline ? nil : 12 * 3600)
        var note = "cached"
        if html == nil && !offline {
            do {
                let d = try await HTTP.get(url, headers: ["Accept-Language": "en-US"])
                if parse(String(decoding: d, as: UTF8.self)).filter({ $0.product == "macOS" }).count >= 5 {
                    cache.store("apple-security-releases.html", d); html = d; note = "downloaded"
                } else { note = "page format not recognized" }
            } catch { note = "download failed (\(error))" }
            if html == nil { html = cache.data("apple-security-releases.html") }
        }
        let rel = html.map { parse(String(decoding: $0, as: UTF8.self)) } ?? []
        let state: SourceStatus.State = rel.isEmpty ? .failed : (note == "cached" || note == "downloaded" ? .ok : .warning)
        return (rel, SourceStatus(name: "Apple security releases", state: state, detail: rel.isEmpty ? "index unavailable (\(note))" : "\(rel.count) releases (\(note))", count: rel.count, updated: FS.mtime(cache.url("apple-security-releases.html").path)))
    }

    static func decode(_ s: String) -> String {
        s.replacingOccurrences(of: "<[^>]+>", with: " ", options: .regularExpression)
            .replacingOccurrences(of: "&nbsp;", with: " ").replacingOccurrences(of: "&amp;", with: "&")
            .replacingOccurrences(of: "&#39;", with: "'").replacingOccurrences(of: "&rsquo;", with: "'").replacingOccurrences(of: "&quot;", with: "\"")
            .replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression).trimmed
    }

    static let dateFormats: [DateFormatter] = ["d MMM yyyy", "MMM d, yyyy", "d MMMM yyyy", "MMMM d, yyyy", "yyyy-MM-dd"].map {
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.timeZone = TimeZone(identifier: "UTC"); f.dateFormat = $0; return f
    }

    public static func parse(_ html: String) -> [AppleRelease] {
        var out: [AppleRelease] = []
        for row in html.allMatches(#"<tr[^>]*>([\s\S]*?)</tr>"#, options: .caseInsensitive) {
            let cells = row[1].allMatches(#"<t[dh][^>]*>([\s\S]*?)</t[dh]>"#, options: .caseInsensitive).map { $0[1] }
            guard cells.count >= 3 else { continue }
            let name = decode(cells[0])
            let ds = decode(cells[cells.count - 1])
            guard !name.isEmpty, let date = dateFormats.lazy.compactMap({ $0.date(from: ds) }).first else { continue }
            var link = cells[0].firstMatch(#"href="([^"]+)""#)?[1] ?? ""
            if link.hasPrefix("/") { link = "https://support.apple.com" + link }
            let os = name.firstMatch(#"^macOS\s+(?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s+)?(\d+(?:\.\d+)*)\b"#)
            let saf = name.firstMatch(#"^Safari\s+(\d+(?:\.\d+)*)\b"#)
            out.append(AppleRelease(name: name, product: os != nil ? "macOS" : saf != nil ? "Safari" : "other",
                                    version: os?[1] ?? saf?[1] ?? "", date: date, link: link, hasCVEs: !link.isEmpty))
        }
        return out
    }

    /// Releases in the same major line that are newer than `installed`, oldest first.
    public static func behind(_ rel: [AppleRelease], product: String, installed: String) -> (latest: String?, newer: [AppleRelease]) {
        let major = installed.split(separator: ".").first.map(String.init) ?? ""
        let line = rel.filter { $0.product == product && $0.version.split(separator: ".").first.map(String.init) == major }
            .sorted { Version.compare($0.version, $1.version) > 0 }
        let newer = line.filter { Version.compare($0.version, installed) > 0 }.sorted { $0.date < $1.date }
        return (line.first?.version, newer)
    }
}
