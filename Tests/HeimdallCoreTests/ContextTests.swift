import XCTest
@testable import HeimdallCore

// The four things a scan now says about a finding beyond the advisory itself: what is bundled
// inside what, whether it is reachable, how long it has been here, and whether anyone is ever
// going to fix it.

/// Package names come from metadata, so the check that gates every copyable command gets its
/// own tests.
final class PackageNameTests: XCTestCase {
    func testVersionedFormulaNamesSurviveValidation() {
        // Homebrew's versioned formulae are exactly the ones that reach end of life, so a command
        // naming them has to get past the name check — and nothing else should.
        var p = Package(ecosystem: .homebrew, name: "openssl@1.1", version: "1.1.1w")
        p.outdated = true
        XCTAssertEqual(Scanner.fixHint(p, []), "brew upgrade 'openssl@1.1'")
        XCTAssertTrue(Scanner.isPackageName("python@3.9"))
        XCTAssertTrue(Scanner.isPackageName("homebrew/core/node@18"))
        XCTAssertTrue(Scanner.isPackageName("@scope/pkg"))
        for bad in ["x; printf INJECTED", "--config=evil", "@", "openssl@", "@1.1", "name\ncommand", "$(id)", "openssl@1.1;id"] {
            XCTAssertFalse(Scanner.isPackageName(bad), bad)
        }
    }
}
