# Heimdall

Heimdall is a native macOS app that inventories the software on your Mac and checks it against published vulnerabilities. Anything on CISA's Known Exploited Vulnerabilities (KEV) list goes to the top of the page. The interface is a native Mac layout in the spirit of Things: a sidebar of sections, a quiet one-line verdict, and rows that open into cards. 

Claude acted as the development agent, with human analysis driving the need.

It runs entirely as **your user account**. You don't need root, an admin password, Full Disk Access or a helper daemon. Heimdall reads metadata your account can already read, and it never changes anything.

## What it reads

| Source | How | Matched with |
|---|---|---|
| macOS, Safari | `SystemVersion.plist`, Safari's `Info.plist` | Apple security-release index + NVD (`cpe:o:apple:macos`) + Apple KEV entries |
| Applications | `Info.plist` of bundles in `/Applications`, `/Applications/*/`, `~/Applications` | NVD by CPE and version (built-in map of ~70 apps, extendable) + KEV |
| Homebrew formulae & casks | `brew info --json=v2 --installed` | `brew vulns --json` if your Homebrew has it, else OSV.dev by upstream git tag |
| Python | `*.dist-info/METADATA` in system, Homebrew, user, pipx, uv, pyenv, conda and brew-vendored site-packages | OSV.dev (PyPI) |
| npm | `package.json` in global `node_modules` (Homebrew, nvm, volta, fnm, bun, pnpm); dependencies optional | OSV.dev (npm) |
| cargo | `~/.cargo/.crates2.json` | OSV.dev (crates.io) |
| Ruby gems | gem specifications outside `/System` | OSV.dev (RubyGems) |
| Go binaries | build info embedded in binaries in `~/go/bin` (optionally Homebrew's bin), parsed directly | OSV.dev (Go, incl. `stdlib`) |
| Browser extensions | `manifest.json` in Chrome, Brave, Edge, Vivaldi, Arc and Opera profiles; Firefox `extensions.json` | A community list of ~8,300 Chrome Web Store IDs removed for malware |

**Vendor advisories** add exact fixed versions, often days ahead of NVD: Apple's per-release security notes for the macOS and Safari releases you're missing, Chrome Releases (stable channel), Mozilla Foundation Security Advisories (Firefox, ESR, Thunderbird), and Microsoft's MSRC monthly releases (Office for Mac, Teams, Edge, VS Code, matched by build number).

**Exploited and exploitable.** Every advisory is checked against CISA KEV, Microsoft's "Exploited: Yes", ENISA's EUVD exploited list, VulnCheck KEV (with a free token), and CISA's Vulnrichment SSVC "exploitation: active". Public exploit code is flagged from Exploit-DB, Metasploit and nuclei templates (your `~/nuclei-templates` checkout when present). FIRST EPSS adds the 30-day exploitation probability. Advisories with no score get one from the CVE record (cvelistV5) or CISA's Vulnrichment.

**Updates available.** Each app's own Sparkle feed, the Mac App Store, and Homebrew's cask index say whether a newer version exists, CVEs or not.

**The icon turns red** while anything exploited (or a malicious extension) is installed. It goes back to normal once that's fixed or ignored.

Matches come from published affected-version ranges, except where noted *inferred*: a KEV entry NVD hasn't analysed for your app yet (say, a fresh Chromium bug in Brave) is flagged when the copy on disk is older than the listing.

## What leaves the Mac

- **OSV.dev:** package names and versions.
- **NVD:** product names and versions, e.g. `mozilla:firefox:144.0`.
- **App Store:** bundle IDs of App Store apps. **Sparkle feeds:** each app's own update URL is fetched.
- **Vendor feeds, Exploit-DB, Metasploit, nuclei, cask index, EUVD, cvelistV5:** plain downloads (CVE IDs in the URL for cvelistV5/Vulnrichment). **VulnCheck:** your token.
- **FIRST EPSS:** CVE ids.
- **CISA KEV catalog and Apple's security-release index:** plain downloads.

No paths, file contents or host names are sent. Offline mode (in Settings) uses cached data only.

## Build

You need macOS 14 or later and Swift 5.10 or later (Xcode or the Command Line Tools).

```bash
git clone https://github.com/rgregory/heimdall.git && cd heimdall
scripts/build-app.sh            # → build/Heimdall.app and build/heimdall-scan
scripts/build-app.sh --install  # …and copies the app to ~/Applications
```

For development, `swift run Heimdall` runs the app and `swift test` runs the core tests. To work in Xcode, open `Package.swift`.

The app is signed ad hoc, so the first launch needs a right-click → **Open**.

## Using it

- **⌘R** scans. The first scan without an NVD API key takes a few minutes, because NVD allows 5 requests per 30 s. Answers are cached for a day. A free key (Settings → Matching) is kept in your login keychain.
- **Brief:** the exploited flaws to fix first, each with a copyable fix command, then this Mac's macOS and Safari status, counts by severity and by section, and what changed since the last scan.
- **Exploited and section pages** (macOS & Safari, Applications, Homebrew, Languages): one row per vulnerable package. Click a row to open it into a card with its fix command and advisories. Click an advisory to see everything about it.
- **Advisories:** every advisory in one sortable list. **Inventory:** everything examined. **Sources:** what was read and how fresh it is.
- Results show up as soon as the fast checks finish. The slower NVD lookups for apps and macOS fill in as they arrive.
- **Ignoring:** right-click an advisory, or use the ⋯ menu on a package. Ignored items stay out of counts and the Dock badge.
- **Export:** JSON (the full report) or CSV (one row per advisory).
- Rescans run automatically every 12 hours while the app is open. You can change that in Settings → Display.

### Headless

```bash
build/heimdall-scan                 # summary to stdout
build/heimdall-scan --json > r.json # full report; exit status 2 if anything known-exploited is present
build/heimdall-scan --save          # also update the report the app shows
NVD_API_KEY=… build/heimdall-scan --no-apps --csv
```

### Teaching it about more apps

Add entries to `~/Library/Application Support/Heimdall/app-cpe.json` (Settings → Matching → *Edit app → CPE mappings…*). Your entries take priority over the built-in list:

```json
[{ "bundleID": "com.example.App", "cpe": ["example:app"], "kevVendor": "^example$", "kevProduct": "app" }]
```

## Layout

```
Sources/HeimdallCore/      collectors, feeds (KEV, OSV, NVD, EPSS, Apple), matching, report store
Sources/Heimdall/          SwiftUI app
Sources/heimdall-scan/     command-line scanner
Tests/HeimdallCoreTests/   version ordering, CVSS, NVD applicability, parsers
```

Data lives in `~/Library/Application Support/Heimdall` (reports, CPE overrides) and `~/Library/Caches/Heimdall` (feeds; safe to delete).

## Limits

- Only what your account can see. Apps installed per-user elsewhere, system daemons and other users' packages aren't covered. Argus covers the root-level view.
- Microsoft Office for Mac is left out of NVD matching on purpose. NVD describes Office by release year and channel, not build number, so version matching would be noise.
- Homebrew formulae without `brew vulns` only match when OSV knows the upstream repo and the release tag lines up with the version.
- Go vulnerability data carries no CVSS, so Go findings show as *unrated* unless they're on KEV.

## License

Apache 2.0. See [LICENSE](LICENSE).
