# Heimdall overview

Details behind the [README](../README.md): how matching works, how rows are ranked, what coverage and "fixed" mean, what leaves the Mac, and how to teach Heimdall about more apps.

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

Matches come from published ranges of affected versions. The exception is anything marked *inferred*: when NVD hasn't analysed a KEV entry for your app yet (a new Chromium bug in Brave, say), Heimdall flags it if your copy is older than the listing.

## Advisories and fixes

Vendor advisories give exact fixed versions, often days before NVD does. Heimdall reads Apple's per-release security notes for the macOS and Safari releases you're missing, Chrome Releases (stable channel), Mozilla Foundation Security Advisories (Firefox, ESR, Thunderbird), and Microsoft's monthly MSRC releases (Office for Mac, Teams, Edge and VS Code, matched by build number).

Every advisory is checked against CISA KEV, Microsoft's "Exploited: Yes", ENISA's EUVD exploited list, VulnCheck KEV (with a free token), and CISA's Vulnrichment SSVC "exploitation: active". Public exploit code is flagged from Exploit-DB, Metasploit and nuclei templates (your `~/nuclei-templates` checkout when present). FIRST EPSS adds the probability of exploitation in the next 30 days. Advisories with no score get one from the CVE record (cvelistV5) or CISA's Vulnrichment.

Each app's own Sparkle feed, the Mac App Store, and Homebrew's cask index say whether a newer version exists. Heimdall only brings up an update when it fixes a security issue. Other updates are listed in Inventory.

Sometimes no advisory names a released version newer than the one installed, and Homebrew has nothing newer either. Heimdall then says there's no fixed release yet, rather than suggesting an upgrade that won't change anything. This happens a lot with OSS-Fuzz reports that were fixed in a commit nobody has released yet.

## Reachability, age and maintenance

Three questions about this Mac, asked after the inventory is read and folded into the ranking:

- **Is it reachable?** `ps -axo pid=,comm=` for what's running, `lsof -nP -iTCP -sTCP:LISTEN` for what's listening (this account only, without root), the LaunchAgent and LaunchDaemon plists a normal user can read, and `launchctl list` for what launchd has loaded. A package is matched to a process by path — an app bundle prefix, a Homebrew keg, the `opt` link `brew services` starts it through, or the `bin` symlink Homebrew links it to — and a formula loaded as `homebrew.mxcl.<name>` counts as started by launchd. `ps`, `lsof` and `launchctl` only ever run from `/bin` and `/usr/sbin`, never from PATH, so a look-alike earlier on a user-writable PATH can't vouch that nothing is running. A library inside an interpreter can't be seen running, so it is left unanswered rather than called idle, and a browser extension follows its browser. Nothing is launched and no process is inspected.
- **How long has it been open?** First sightings are kept in `history.json`, keyed by package and advisory without the version, so an advisory that survives a patch release is the same open problem rather than a new one. A finding over a week old is pushed up, and the row says since when. The same file keeps one small row per scan — counts only — for the trend.
- **Will anyone fix it?** `brew info` reports its own deprecated and disabled formulae and casks, with Homebrew's reason and replacement. npm, PyPI and crates.io are asked whether the installed release was yanked or the package deprecated, for packages that already have an advisory, capped at 60 a scan and cached for a week. A dated table of release calendars covers runtimes past end of life — Python, Node, Ruby, OpenSSL, PHP and PostgreSQL formulae. Because the table is dated, an entry only counts from the day it expires, and a stale copy under-reports instead of inventing something.

## Ranking

Rows are ordered by risk, not by CVSS alone. Known exploitation, ransomware use, public exploit code and EPSS push a finding up, and so do a socket it's listening on, a process that's running right now, a launchd job that starts it, and weeks of sitting open. Having nothing to install pushes it down, as does being a dependency bundled inside something else rather than a program you run, or not running at all when the scan went past. Open any row and it tells you which of those applied, what it saw running, and how long the finding has been here.

**Not Maintained** collects what nobody is going to fix: deprecated or disabled Homebrew formulae, releases yanked from npm, PyPI or crates.io after they shipped, and runtimes past their own end of life. There is no version to upgrade to, so the advice is to remove or replace them, and they appear even when nothing has been published against them yet. One inside an app isn't yours to uninstall: that one waits on the app's next build.

## News

The last 30 days from SANS ISC, The Hacker News, Krebs, Sophos, Securelist, WeLiveSecurity, Schneier, Troy Hunt, Graham Cluley, Darknet Diaries and USOM (TR-CERT). Stories are highlighted red when they name a CVE that's open on this Mac and pink when they name software you have installed. Darknet Diaries episodes are listed but never matched. Findings in the news get a newspaper icon, and the Brief shows this week's stories about your Mac. You can edit the feed list in Settings → News.

## Coverage, remediation and exceptions

Inventory shows each package's primary matcher outcome: checked, no product mapping, lookup unavailable, not checked, cached data only, or still checking. Hover for details; the Brief links to coverage gaps and source warnings. "Checked" describes that matcher, not a guarantee that the software is safe, and vendor-only checks remain partial coverage.

**Verify fix (rescan)** runs a full scan and reports whether the finding is still detected, fixed, removed, no longer checked, or unconfirmed. "Since the Last Scan" uses the same distinctions. A disappearance at the same version is unconfirmed; changed scan settings, missing coverage, offline caches and source warnings cannot confirm an upgrade as a fix. Ignoring a finding never counts as fixing it.

An **exception** takes a reason, a scope of this version, this installation or this advisory, and an expiry of 7, 30 or 90 days. Exceptions hide matching findings from totals and badges, and are reviewed at least once a minute while the app is running. Newly known exploitation reopens the finding. Accepting a known-exploited advisory only suppresses that specific advisory, even with a broader scope. Settings → Display lists exceptions and lets you remove them. Old ignores migrate to installation-specific advisory exceptions that expire after 30 days.

Coverage is stored with each package and included in JSON reports and advisory CSV rows. It records the primary matching path (NVD, OSV, Homebrew advisories, or the malicious-extension list), rather than inferring success from an empty finding list. Offline checks are explicitly marked cached. Online caches within the matcher's normal lifetime can count as completed checks; failed NVD refreshes that fall back to stale data cannot. A Homebrew advisory response must identify a formula to establish its coverage. OSV's GIT-tag fallback is best effort and cannot confirm remediation because an empty result does not establish that the upstream tag exists. Vendor-only matches can still produce findings while primary coverage remains incomplete.

Reports retain their scan options. Fix verification is conservative: the scope must match the prior report, the installed version must increase, its primary check must complete, and no source warnings or failures may be present. Removal requires an unchanged online scan scope and a successful corresponding inventory collector, and means the installation disappeared from that inventory — it does not prove that every copy on disk was removed. Older reports remain readable but need a new baseline scan before verification can establish these outcomes. Any source warning currently prevents confirming a fix, including warnings from optional sources.

Exceptions live in local preferences, with installation identity, optional advisory identity, accepted version, reason, expiry, and whether exploitation was already known. Homebrew keg paths and Chromium extension version directories are normalized so installation identity survives upgrades. Separate installation paths remain separate scopes. The app's report comparison uses unfiltered findings, so an exception does not become evidence of remediation. The CLI continues reporting all findings and does not apply app exceptions.

## What leaves the Mac

- **OSV.dev:** package names and versions.
- **NVD:** product names and versions, e.g. `mozilla:firefox:144.0`.
- **App Store:** bundle IDs of App Store apps. **Sparkle feeds:** each app's own update URL is fetched.
- **News feeds, vendor feeds, Exploit-DB, Metasploit, nuclei, cask index, EUVD, cvelistV5:** plain downloads (CVE IDs in the URL for cvelistV5/Vulnrichment). **VulnCheck:** your token.
- **FIRST EPSS:** CVE ids.
- **npm, PyPI, crates.io:** the name and version of a package that already has an advisory.
- **CISA KEV catalog and Apple's security-release index:** plain downloads.
- **GitHub:** one request a day to the latest-release endpoint of this repository, when update checks are on.

No paths, file contents, host names or cookies are sent. Cookie and credential storage are both refused, so nothing a server sets comes back on a later request, and an API key travels only in the header of the request that needs it — `apiKey` for NVD, a bearer token for VulnCheck. Offline mode (in Settings) uses cached data only and skips `brew vulns`.

External responses are size-limited while downloading: 2 MiB per Sparkle feed, 32 MiB for ordinary responses, 64 MiB for the cask and Exploit-DB indexes, and 128 MiB for Metasploit. OSV follows every pagination token; malformed or incomplete OSV and NVD responses are rejected instead of being cached as clean results. If a refresh fails, the previous cache is kept and Sources reports reduced coverage. Every request goes through one connection pool, so repeated lookups to the same host reuse an open connection and its TLS session rather than handshaking again, up to eight connections per host.

Heimdall doesn't run your login shell to learn PATH: child processes get `/usr/bin`, `/bin`, Homebrew's prefixes and the usual per-user tool folders, plus anything added under Settings → Background (or `HEIMDALL_EXTRA_PATH` for `heimdall-scan`). Versions are compared by each ecosystem's own rules — PEP 440 for Python, SemVer for npm, cargo and Go — so a post release of the fixed version isn't mistaken for an older one.

Copyable fix commands validate package names and fixed versions and quote their arguments. CSV exports neutralize spreadsheet formula prefixes in external text.

## Limits

- Microsoft Office for Mac is left out of NVD matching on purpose. NVD describes Office by release year and channel, not build number, so matching on version would mostly produce false hits.
- Homebrew formulae without `brew vulns` only match when OSV knows the upstream repo and the release tag lines up with the version.
- Go vulnerability data carries no CVSS, so Go findings show as *unrated* unless they're on KEV.
- A Chromium version is only read out of an app's framework when it is shaped like one, so CEF copies are listed in Inventory without matching and Chromium findings inside an app are marked *inferred* until NVD analyses the entry for that engine. [How matching works](#how-matching-works) gives the version shapes.
- Withdrawn releases are checked for npm, PyPI and crates.io packages that already have an advisory, up to 60 a scan. Ruby gems aren't covered, and neither is a project that simply stopped getting commits.

## Teaching it about more apps

Add entries to `~/Library/Application Support/Heimdall/app-cpe.json` (Settings → Matching → *Edit app → CPE mappings…*). Your entries take priority over the built-in list:

```json
[{ "bundleID": "com.example.App", "cpe": ["example:app"], "kevVendor": "^example$", "kevProduct": "app" }]
```
