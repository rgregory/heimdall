import Foundation

/// macOS version and host facts, all readable without privileges.
public enum SystemCollector {
    public static func collect() -> (posture: SystemPosture, packages: [Package], status: SourceStatus) {
        var p = SystemPosture()
        p.hostName = ProcessInfo.processInfo.hostName.replacingOccurrences(of: ".local", with: "")
        if let d = FS.read("/System/Library/CoreServices/SystemVersion.plist"),
           let pl = (try? PropertyListSerialization.propertyList(from: d, format: nil)) as? [String: Any] {
            p.osVersion = pl["ProductVersion"] as? String ?? ""
            p.osBuild = pl["ProductBuildVersion"] as? String ?? ""
        } else {
            let v = ProcessInfo.processInfo.operatingSystemVersion
            p.osVersion = "\(v.majorVersion).\(v.minorVersion)" + (v.patchVersion > 0 ? ".\(v.patchVersion)" : "")
        }
        var pkgs: [Package] = []
        if !p.osVersion.isEmpty {
            pkgs.append(Package(ecosystem: .macos, name: "macOS", version: p.osVersion, location: "/System", source: "SystemVersion.plist"))
        }
        let status = SourceStatus(name: "macOS", state: p.osVersion.isEmpty ? .failed : .ok,
                                  detail: p.osVersion.isEmpty ? "could not read the macOS version" : "macOS \(p.osVersion) (\(p.osBuild))", count: pkgs.count, updated: Date())
        return (p, pkgs, status)
    }
}
