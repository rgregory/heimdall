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
- **CISA KEV catalog and Apple's security-release index:** plain downloads.

No paths, file contents or host names are sent. Offline mode (in Settings) uses cached data only and skips `brew vulns`.

External responses are size-limited while downloading: 2 MiB per Sparkle feed, 32 MiB for ordinary responses, 64 MiB for the cask and Exploit-DB indexes, and 128 MiB for Metasploit. OSV follows every pagination token; Malformed or incomplete OSV and NVD responses are rejected instead of being cached as clean results. If a refresh fails, the previous cache is kept and Sources reports reduced coverage.

Copyable fix commands validate package names and fixed versions and quote their arguments. CSV exports neutralize spreadsheet formula prefixes in external text.

## Teaching it about more apps

Add entries to `~/Library/Application Support/Heimdall/app-cpe.json` (Settings → Matching → *Edit app → CPE mappings…*). Your entries take priority over the built-in list:

```json
[{ "bundleID": "com.example.App", "cpe": ["example:app"], "kevVendor": "^example$", "kevProduct": "app" }]
```
