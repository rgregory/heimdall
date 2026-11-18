# Heimdall overview

Details behind the [README](../README.md): how matching works, what leaves the Mac, and how to teach Heimdall about more apps.

## How matching works

| Installed software | Read from | Matched with |
|---|---|---|
| macOS, Safari | `SystemVersion.plist`, Safari's `Info.plist` | Apple security-release index and per-release notes, NVD (`cpe:o:apple:macos`), Apple KEV entries |
| Applications | `Info.plist` of bundles in `/Applications`, `/Applications/*/`, `~/Applications` | NVD by CPE and version (built-in map of ~70 apps, extendable), plus KEV |
| Homebrew formulae & casks | `brew info --json=v2 --installed` | `brew vulns --json` if your Homebrew has it, else OSV.dev by upstream git tag |
| Python | `*.dist-info/METADATA` in system, Homebrew, user, pipx, uv, pyenv, conda and brew-vendored site-packages | OSV.dev (PyPI) |
| npm | `package.json` in global `node_modules` (Homebrew, nvm, volta, fnm, bun, pnpm); dependencies optional | OSV.dev (npm) |
| cargo | `~/.cargo/.crates2.json` | OSV.dev (crates.io) |
| Ruby gems | gem specifications outside `/System` | OSV.dev (RubyGems) |
| Go binaries | build info embedded in binaries in `~/go/bin` (optionally Homebrew's bin), parsed directly | OSV.dev (Go, incl. `stdlib`) |
| Browser extensions | `manifest.json` in Chrome, Brave, Edge, Vivaldi, Arc and Opera profiles; Firefox `extensions.json` | A community list of ~8,300 Chrome Web Store IDs removed for malware |
| Runtimes inside apps | `Contents/Frameworks/{Electron Framework,Chromium Embedded Framework,Sparkle,Python}.framework` and a bundled JRE's `release` file | NVD by CPE, as a child of the host app |

Apple's own bundles are skipped there — they move with macOS — except Safari and Xcode. A nested framework's version decides what it can be compared against. Four numeric parts with a major in the low hundreds *and* a build number in the thousands is a Chromium version, and is matched as Chromium. Two or three parts is Electron's own, and is matched as Electron. CEF's numbering takes Chromium's major and continues with its own small numbers (`156.0.15.0` is CEF 156.0.15, whose engine is really 156.0.8011.x), so it matches nothing published and is inventory only — comparing it against Chrome's ranges would mark every advisory in that major line as present here. The fix for any of them is a new build of the host app, never the framework, and the advice says so.

## Reachability, age and maintenance

Three questions about this Mac, asked after the inventory is read and folded into the ranking:

- **Is it reachable?** `ps -axo pid=,comm=` for what's running, `lsof -nP -iTCP -sTCP:LISTEN` for what's listening (this account only, without root), the LaunchAgent and LaunchDaemon plists a normal user can read, and `launchctl list` for what launchd has loaded. A package is matched to a process by path — an app bundle prefix, a Homebrew keg or the `bin` symlink Homebrew links it to. A library inside an interpreter can't be seen running, so it is left unanswered rather than called idle, and a browser extension follows its browser. Nothing is launched and no process is inspected.
- **How long has it been open?** First sightings are kept in `history.json`, keyed by package and advisory without the version, so an advisory that survives a patch release is the same open problem rather than a new one. A finding over a week old is pushed up, and the row says since when. The same file keeps one small row per scan — counts only — for the trend.
- **Will anyone fix it?** `brew info` reports its own deprecated and disabled formulae and casks, with Homebrew's reason and replacement. npm, PyPI and crates.io are asked whether the installed release was yanked or the package deprecated, for packages that already have an advisory, capped at 60 a scan and cached for a week. A dated table of release calendars covers runtimes past end of life — Python, Node, Ruby, OpenSSL, PHP and PostgreSQL formulae. Because the table is dated, an entry only counts from the day it expires, and a stale copy under-reports instead of inventing something.

Vendor advisories give exact fixed versions, often days before NVD does. Heimdall reads Apple's per-release security notes for the macOS and Safari releases you're missing, Chrome Releases (stable channel), Mozilla Foundation Security Advisories (Firefox, ESR, Thunderbird), and Microsoft's monthly MSRC releases (Office for Mac, Teams, Edge and VS Code, matched by build number).

Every advisory is checked against CISA KEV, Microsoft's "Exploited: Yes", ENISA's EUVD exploited list, VulnCheck KEV (with a free token), and CISA's Vulnrichment SSVC "exploitation: active". Public exploit code is flagged from Exploit-DB, Metasploit and nuclei templates (your `~/nuclei-templates` checkout when present). FIRST EPSS adds the probability of exploitation in the next 30 days. Advisories with no score get one from the CVE record (cvelistV5) or CISA's Vulnrichment.

Each app's own Sparkle feed, the Mac App Store, and Homebrew's cask index say whether a newer version exists. Heimdall only brings up an update when it fixes a security issue. Other updates are listed in Inventory.

Sometimes no advisory names a released version newer than the one installed, and Homebrew has nothing newer either. Heimdall then says there's no fixed release yet, rather than suggesting an upgrade that won't change anything. This happens a lot with OSS-Fuzz reports that were fixed in a commit nobody has released yet.

Matches come from published ranges of affected versions. The exception is anything marked *inferred*: when NVD hasn't analysed a KEV entry for your app yet (a new Chromium bug in Brave, say), Heimdall flags it if your copy is older than the listing.

## What leaves the Mac

- **OSV.dev:** package names and versions.
- **NVD:** product names and versions, e.g. `mozilla:firefox:144.0`.
- **App Store:** bundle IDs of App Store apps. **Sparkle feeds:** each app's own update URL is fetched.
- **News feeds, vendor feeds, Exploit-DB, Metasploit, nuclei, cask index, EUVD, cvelistV5:** plain downloads (CVE IDs in the URL for cvelistV5/Vulnrichment). **VulnCheck:** your token.
- **FIRST EPSS:** CVE ids.
- **npm, PyPI, crates.io:** the name and version of a package that already has an advisory.
- **CISA KEV catalog and Apple's security-release index:** plain downloads.

No paths, file contents or host names are sent. Offline mode (in Settings) uses cached data only and skips `brew vulns`.

External responses are size-limited while downloading: 2 MiB per Sparkle feed, 32 MiB for ordinary responses, 64 MiB for the cask and Exploit-DB indexes, and 128 MiB for Metasploit. OSV follows every pagination token; Malformed or incomplete OSV and NVD responses are rejected instead of being cached as clean results. If a refresh fails, the previous cache is kept and Sources reports reduced coverage.

Copyable fix commands validate package names and fixed versions and quote their arguments. CSV exports neutralize spreadsheet formula prefixes in external text.

## Teaching it about more apps

Add entries to `~/Library/Application Support/Heimdall/app-cpe.json` (Settings → Matching → *Edit app → CPE mappings…*). Your entries take priority over the built-in list:

```json
[{ "bundleID": "com.example.App", "cpe": ["example:app"], "kevVendor": "^example$", "kevProduct": "app" }]
```

## Coverage, remediation and exceptions

Coverage is stored with each package and included in JSON reports and advisory CSV rows. It records the primary matching path (NVD, OSV, Homebrew advisories, or the malicious-extension list), rather than inferring success from an empty finding list. Offline checks are explicitly marked cached. Online caches within the matcher's normal lifetime can count as completed checks; failed NVD refreshes that fall back to stale data cannot. A Homebrew advisory response must identify a formula to establish its coverage. OSV's GIT-tag fallback is best effort and cannot confirm remediation because an empty result does not establish that the upstream tag exists. Vendor-only matches can still produce findings while primary coverage remains incomplete.

Reports now retain their scan options. Fix verification is conservative: the scope must match the prior report, the installed version must increase, its primary check must complete, and no source warnings or failures may be present. A same-version disappearance is unconfirmed. Removal requires an unchanged online scan scope and a successful corresponding inventory collector. A removal means the installation disappeared from that inventory; it does not prove that every copy on disk was removed. Older reports remain readable but need a new baseline scan before verification can establish these outcomes. Any source warning currently prevents confirming a fix, including warnings from optional sources.

Exceptions live in local preferences, with installation identity, optional advisory identity, accepted version, reason, expiry, and whether exploitation was already known. Homebrew keg paths and Chromium extension version directories are normalized so installation identity survives upgrades. Separate installation paths remain separate scopes. The app's report comparison uses unfiltered findings, so an exception does not become evidence of remediation. The CLI continues reporting all findings and does not apply app exceptions.
