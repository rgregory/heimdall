# Heimdall

Heimdall is a macOS app that lists the software on your Mac and checks it against published vulnerabilities. Anything on CISA's Known Exploited Vulnerabilities (KEV) list goes to the top. The layout borrows from Things: a sidebar of sections, a one-line verdict, and rows you click to open.

Claude wrote the code. A person decided what it needed to do and checked the results.

| Brief | Exploited timeline |
|---|---|
| ![The Brief: a one-line verdict and macOS/Safari status](docs/screenshots/brief.png) | ![The Exploited page: CISA KEV listings that touch this Mac, as a month-grouped timeline](docs/screenshots/exploited.png) |
| A one-line verdict, the packages behind it, and macOS and Safari status. | CISA's exploited listings over time. This Mac shows only what touches your installed software. Everything shows the whole feed. |

It runs as your normal user account. It doesn't need root, an admin password, Full Disk Access or a helper daemon. It only reads metadata your account can already read, and it never changes anything.

## Sources

| Installed software | Read from | Checked against |
|---|---|---|
| macOS, Safari | `SystemVersion.plist`, `Info.plist` | Apple security releases and per-release notes, NVD |
| Apps | `Info.plist` in `/Applications`, `~/Applications` | NVD (~70 mapped apps), Chrome Releases, Mozilla MFSA, Microsoft MSRC |
| Homebrew | `brew info --installed` | `brew vulns`, else OSV.dev |
| Python, npm, cargo, gems | package metadata on disk | OSV.dev |
| Go binaries | embedded build info | OSV.dev (Go, incl. `stdlib`) |
| Browser extensions | Chromium and Firefox profiles | malicious-extension list |

Each advisory is then checked for signs of exploitation (CISA KEV, MSRC, EUVD, VulnCheck, CISA SSVC) and for public exploit code (Exploit-DB, Metasploit, nuclei). FIRST EPSS gives the odds of exploitation, and cvelistV5 or CISA Vulnrichment fill in missing scores. Sparkle feeds, the App Store and Homebrew's cask index say when a newer version is out, and 13 news feeds are matched against what's installed. The app icon turns red while anything exploited is installed.

[docs/OVERVIEW.md](docs/OVERVIEW.md) covers what gets sent where, download size limits, and adding your own app mappings.

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

- **⌘R** scans. Without an NVD API key the first scan takes a few minutes, because NVD only allows 5 requests every 30 seconds. Answers are cached for a day. You can add a free key in Settings → Matching; it's stored in your login keychain.
- **Brief:** the exploited flaws to fix first, each with steps and commands you can copy. Below that are the macOS and Safari status, counts by severity and section, and what changed since the last scan.
- **Exploited:** a timeline of CISA KEV listings, grouped by month, with same-day listings for one product folded into a single line. A red dot means a vulnerable version is installed now; a green ring means the product is installed but no vulnerable version was found. You can switch between This Mac and Everything, and between 30 days, 90 days and 12 months.
- **News:** the last 30 days from SANS ISC, The Hacker News, Krebs, Sophos, Securelist, WeLiveSecurity, Schneier, Troy Hunt, Graham Cluley, Darknet Diaries and USOM (TR-CERT). Stories are highlighted red when they name a CVE that's open on this Mac and pink when they name software you have installed. Darknet Diaries episodes are listed but never matched. Findings in the news get a newspaper icon, and the Brief shows this week's stories about your Mac. You can edit the feed list in Settings → News.
- **Section pages** (macOS, Apps, Homebrew, Languages): one row per vulnerable package. Click a row to see how to fix it and which advisories apply, then click an advisory for the full details. Languages groups packages under the tool that bundles them.
- **Advisories** lists every advisory in one sortable table. **Inventory** lists everything that was checked. **Sources** shows what was read and how recent it is.
- Results appear as soon as the fast checks finish. The slower NVD lookups for apps and macOS fill in afterwards.
- **Ignoring:** right-click an advisory, or use the ⋯ menu on a package. Ignored items don't count toward the totals or the Dock badge.
- **Export:** JSON (the full report) or CSV (one row per advisory).
- While the app is open it rescans every 12 hours. You can change the interval in Settings → Display.

### Headless

```bash
build/heimdall-scan                 # summary to stdout
build/heimdall-scan --json > r.json # full report; exit status 2 if anything known-exploited is present
build/heimdall-scan --save          # also update the report the app shows
NVD_API_KEY=… build/heimdall-scan --no-apps --csv
```

## Layout

```
Sources/HeimdallCore/      collectors, feeds (KEV, OSV, NVD, EPSS, Apple), matching, report store
Sources/Heimdall/          SwiftUI app
Sources/heimdall-scan/     command-line scanner
Tests/HeimdallCoreTests/   version ordering, CVSS, NVD applicability, parsers
```

Data lives in `~/Library/Application Support/Heimdall` (reports, [CPE overrides](docs/OVERVIEW.md#teaching-it-about-more-apps)) and `~/Library/Caches/Heimdall` (feeds; safe to delete).

## Limits

- Heimdall only sees what your account can see. Apps installed elsewhere for one user, system daemons and other users' packages aren't covered.
- Microsoft Office for Mac is left out of NVD matching on purpose. NVD describes Office by release year and channel, not build number, so matching on version would mostly produce false hits.
- Homebrew formulae without `brew vulns` only match when OSV knows the upstream repo and the release tag lines up with the version.
- Go vulnerability data carries no CVSS, so Go findings show as *unrated* unless they're on KEV.

## License

Apache 2.0. See [LICENSE](LICENSE).
