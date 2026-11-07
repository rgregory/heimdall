import Foundation
import HeimdallCore

// Headless scan: same engine as the app, for Terminal, cron or launchd.
//   heimdall-scan [--json | --csv] [--offline] [--no-nvd] [--save] [--quiet]
let args = Set(CommandLine.arguments.dropFirst())
if args.contains("-h") || args.contains("--help") {
    print("""
    usage: heimdall-scan [--json | --csv] [--offline] [--no-nvd] [--no-apps] [--save] [--quiet]
      --json / --csv  write the report to stdout instead of a summary
      --offline       cached feeds only
      --no-nvd        skip NVD lookups (apps, macOS, Safari)
      --save          also store the report where the Heimdall app reads it
      NVD_API_KEY, VULNCHECK_TOKEN   environment variables, optional
    """)
    exit(0)
}
var opts = ScanOptions()
opts.offline = args.contains("--offline")
opts.nvd = !args.contains("--no-nvd")
opts.apps = !args.contains("--no-apps")
let quiet = args.contains("--quiet") || args.contains("--json") || args.contains("--csv")
let err = FileHandle.standardError
let env = ProcessInfo.processInfo.environment
let scanner = Scanner(options: opts, nvdAPIKey: env["NVD_API_KEY"], vulnCheckToken: env["VULNCHECK_TOKEN"])
let report = await scanner.run { stage, f in
    if !quiet { err.write(Data(String(format: "[%3.0f%%] %@\n", f * 100, stage).utf8)) }
}
if args.contains("--save") { ReportStore.save(report) }
if args.contains("--json") { FileHandle.standardOutput.write(ReportExport.json(report)); exit(report.kevCount > 0 ? 2 : 0) }
if args.contains("--csv") { print(ReportExport.csv(report), terminator: ""); exit(report.kevCount > 0 ? 2 : 0) }

print("\nTHE HEIMDALL — \(report.posture.hostName), macOS \(report.posture.osVersion)")
print(String(repeating: "═", count: 64))
print("\(report.packages.count) packages examined · \(report.findings.count) vulnerable · \(report.allVulns.count) advisories · \(report.kevCount) known exploited")
if !report.posture.releasesBehind.isEmpty { print("macOS is \(report.posture.releasesBehind.count) security release(s) behind \(report.posture.latestInLine ?? "")") }
if !report.kevFindings.isEmpty {
    print("\nSTOP PRESS — known exploited (CISA KEV)")
    for f in report.kevFindings {
        print("  \(f.package.displayName) \(f.package.version): " + f.vulns.filter(\.isKEV).map(\.headlineID).joined(separator: ", "))
        print("    → \(f.fixHint)")
    }
}
print("\nTop findings")
for f in report.findings.prefix(15) {
    let worst = f.topSeverity.rawValue
    print("  [\(worst)] \(f.package.ecosystem.rawValue) \(f.package.displayName) \(f.package.version) — \(f.vulns.count) advisories → \(f.fixHint)")
}
print("\nSources")
for s in report.sources { print("  \(s.state.rawValue.padding(toLength: 8, withPad: " ", startingAt: 0)) \(s.name): \(s.detail)") }
exit(report.kevCount > 0 ? 2 : 0)
