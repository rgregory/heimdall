import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import XCTest
@testable import HeimdallCore

final class OutputSecurityTests: XCTestCase {
    func testFeedVersionCannotEscapeFixCommand() {
        let payload = "999.0'; printf INJECTED; #"
        let record: [String: Any] = ["id": "TEST-1", "affected": [["package": ["name": "example"], "ranges": [["type": "ECOSYSTEM", "events": [["fixed": payload], ["fixed": "2.0"]]]]]]]
        let v = OSVClient.vulnerability(record, ecosystem: "PyPI", package: "example")
        let p = Package(ecosystem: .pypi, name: "example", version: "1.0")
        let command = Scanner.fixHint(p, [v]).components(separatedBy: "  — ")[0]
        XCTAssertEqual(command, "python3 -m pip install -U 'example>=2.0'")
        let result = Shell.runSync("/bin/sh", ["-c", "python3() { printf '%s\\n' \"$@\"; }; " + command], path: "/usr/bin:/bin", timeout: 5)
        XCTAssertTrue(result.ok)
        XCTAssertEqual(result.stdout, "-m\npip\ninstall\n-U\nexample>=2.0\n")
    }

    func testShellQuotePreservesLiteralMetacharacters() {
        let payload = "x'; printf INJECTED; # $(printf BAD)\nsecond line"
        let result = Shell.runSync("/bin/sh", ["-c", "printf %s " + Shell.quote(payload)], path: "/usr/bin:/bin", timeout: 5)
        XCTAssertTrue(result.ok)
        XCTAssertEqual(result.stdout, payload)
    }

    func testInvalidNamesNeverBecomeCommands() {
        for eco in [Ecosystem.homebrew, .cask, .pypi, .npm, .crates, .rubygems] {
            for name in ["x; printf INJECTED", "--config=evil", "name\ncommand", "$(id)"] {
                let p = Package(ecosystem: eco, name: name, version: "1")
                XCTAssertTrue(Scanner.fixHint(p, []).contains("invalid package name"))
            }
        }
        XCTAssertEqual(Scanner.fixHint(Package(ecosystem: .npm, name: "@scope/pkg", version: "1"), []), "npm install -g '@scope/pkg@latest'")
        var app = Package(ecosystem: .app, name: "Visual Studio Code", version: "1")
        app.cask = "visual-studio-code"
        XCTAssertEqual(Scanner.fixHint(app, []), "brew upgrade --cask 'visual-studio-code'")
    }

    func testCSVNeutralizesFormulaPrefixesAndQuotesCarriageReturns() {
        for value in ["=1+1", "+SUM(A1)", "-1+2", "@SUM(A1)", "  =1+1", "\t=1+1", "\r=1+1", "\n=1+1"] {
            var v = Vulnerability(id: "TEST"); v.summary = value
            let report = ScanReport(generated: Date(), posture: SystemPosture(), packages: [], findings: [Finding(package: Package(ecosystem: .npm, name: "x", version: "1"), vulns: [v])], sources: [])
            let expected = (value.contains("\r") || value.contains("\n")) ? "\"'" + value + "\"" : "'" + value
            XCTAssertTrue(ReportExport.csv(report).hasSuffix("," + expected + "\n"), value)
        }
        var v = Vulnerability(id: "TEST"); v.summary = "plain\rtext"
        let report = ScanReport(generated: Date(), posture: SystemPosture(), packages: [], findings: [Finding(package: Package(ecosystem: .npm, name: "x", version: "1"), vulns: [v])], sources: [])
        XCTAssertTrue(ReportExport.csv(report).hasSuffix(",\"plain\rtext\"\n"))
    }
}

final class FeedSecurityTests: XCTestCase {
    func cache() -> DiskCache {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("heimdall-tests-" + UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return DiskCache(directory: dir)
    }
    func stale(_ cache: DiskCache) throws {
        for file in try FileManager.default.contentsOfDirectory(at: cache.dir, includingPropertiesForKeys: nil) {
            try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSinceNow: -9 * 86400)], ofItemAtPath: file.path)
        }
    }

    func testOSVPaginationKeepsQueryAlignmentAndTokenOnlyPages() async throws {
        let queries = ["one", "two", "three"].enumerated().map { OSVClient.Query(pkgIndex: $0.offset, ecosystem: "npm", name: $0.element, version: "1") }
        var calls = 0
        let ids = try await OSVClient.queryIDs(queries) { data in
            let body = try XCTUnwrap(jsonObject(data) as? [String: Any])
            let sent = try XCTUnwrap(body["queries"] as? [[String: Any]])
            calls += 1
            switch calls {
            case 1:
                XCTAssertEqual(sent.count, 3)
                return Data(#"{"results":[{"vulns":[{"id":"A"}]},{"next_page_token":"t1"},{}]}"#.utf8)
            case 2:
                XCTAssertEqual(sent.count, 1)
                XCTAssertEqual((sent[0]["package"] as? [String: String])?["name"], "two")
                XCTAssertEqual(sent[0]["page_token"] as? String, "t1")
                return Data(#"{"results":[{"vulns":[{"id":"B"}],"next_page_token":"t2"}]}"#.utf8)
            default:
                XCTAssertEqual(sent[0]["page_token"] as? String, "t2")
                return Data(#"{"results":[{"vulns":[{"id":"B"},{"id":"C"}]}]}"#.utf8)
            }
        }
        XCTAssertEqual(calls, 3)
        XCTAssertEqual(ids, [["A"], ["B", "C"], []])
    }

    func testMalformedOSVResponsesFailWithoutCaching() async throws {
        let p = Package(ecosystem: .npm, name: "example", version: "1")
        for response in ["<html>error</html>", "{}", #"{"results":[]}"#, #"{"results":[{"vulns":[{}]}]}"#, #"{"results":[{"vulns":"invalid"}]}"#] {
            let c = cache()
            let (hits, status) = await OSVClient.match([p], offline: false, cache: c, post: { _ in Data(response.utf8) }, get: { _ in XCTFail("unexpected details fetch"); return Data() })
            XCTAssertTrue(hits.isEmpty)
            XCTAssertEqual(status.state, .failed)
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: c.dir.path).isEmpty)
        }
    }

    func testOSVRepeatedTokenFails() async {
        let q = OSVClient.Query(pkgIndex: 0, ecosystem: "npm", name: "a", version: "1")
        do {
            _ = try await OSVClient.queryIDs([q]) { _ in Data(#"{"results":[{"next_page_token":"repeat"}]}"#.utf8) }
            XCTFail("must reject repeated tokens")
        } catch { XCTAssertTrue(String(describing: error).contains("repeated")) }
    }

    func testOSVFailedRefreshPreservesKnownFindings() async throws {
        let c = cache(), p = Package(ecosystem: .npm, name: "example", version: "1")
        _ = await OSVClient.match([p], offline: false, cache: c,
                                 post: { _ in Data(#"{"results":[{"vulns":[{"id":"TEST-1"}]}]}"#.utf8) },
                                 get: { _ in Data(#"{"id":"TEST-1","summary":"known"}"#.utf8) })
        try stale(c)
        let (hits, status) = await OSVClient.match([p], offline: false, cache: c, post: { _ in Data("{}".utf8) }, get: { _ in throw URLError(.notConnectedToInternet) })
        XCTAssertEqual(hits[p.id]?.first?.id, "TEST-1")
        XCTAssertEqual(status.state, .warning)
        let (offlineHits, _) = await OSVClient.match([p], offline: true, cache: c, post: { _ in XCTFail(); return Data() }, get: { _ in XCTFail(); return Data() })
        XCTAssertEqual(offlineHits[p.id]?.first?.summary, "known")
    }

    func testNVDRejectsMalformedAndIncompletePages() throws {
        for raw in ["{}", "html", #"{"startIndex":0,"resultsPerPage":0,"totalResults":2,"vulnerabilities":[]}"#,
                    #"{"startIndex":1,"resultsPerPage":0,"totalResults":1,"vulnerabilities":[]}"#,
                    #"{"startIndex":0,"resultsPerPage":1,"totalResults":1,"vulnerabilities":[{}]}"#] {
            XCTAssertThrowsError(try NVDClient.page(Data(raw.utf8), expectedStart: 0))
        }
        let empty = try NVDClient.page(Data(#"{"startIndex":0,"resultsPerPage":0,"totalResults":0,"vulnerabilities":[]}"#.utf8), expectedStart: 0)
        XCTAssertTrue(empty.cves.isEmpty)
    }

    func testNVDFailedRefreshKeepsStaleCacheAndReportsError() async throws {
        let c = cache()
        let key = "vm-a-vendor-product-1.json"
        c.put(key, [NVDCve(id: "CVE-2025-1234", published: nil, summary: "known", configs: [], references: [])])
        try stale(c)
        let before = c.data(key)
        let client = NVDClient(offline: false, cache: c) { _, _ in Data("{}".utf8) }
        let result = await client.cves(part: "a", vendor: "vendor", product: "product", version: "1")
        XCTAssertEqual(result?.first?.id, "CVE-2025-1234")
        let errors = await client.errors
        XCTAssertEqual(errors.count, 1)
        XCTAssertEqual(c.data(key), before)
    }

    func testNVDLaterMalformedPageDoesNotCachePartialAnswers() async throws {
        let c = cache()
        let client = NVDClient(offline: false, cache: c) { url, _ in
            if url.contains("startIndex=0&") {
                return Data(#"{"startIndex":0,"resultsPerPage":1,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2025-1234"}}]}"#.utf8)
            }
            return Data("{}".utf8)
        }
        let result = await client.cves(part: "a", vendor: "vendor", product: "product", version: "1")
        XCTAssertNil(result)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: c.dir.path).isEmpty)
        let errors = await client.errors
        XCTAssertEqual(errors.count, 1)
    }

    func testOfflineBrewDoesNotInvokeVulnerabilityCommand() async {
        var calls: [[String]] = []
        let result = await BrewCollector.collect(useBrewVulns: true, offline: true, brew: "/fake/brew") { _, args, _ in
            calls.append(args)
            return ShellResult(status: 0, stdout: args == ["--prefix"] ? "/fake" : #"{"formulae":[],"casks":[]}"#, stderr: "", timedOut: false)
        }
        XCTAssertEqual(calls, [["info", "--json=v2", "--installed"], ["--prefix"]])
        XCTAssertNil(result.brewVulns)
        XCTAssertTrue(result.status.contains { $0.name == "brew vulns" && $0.state == .skipped })
    }
}

private final class DownloadProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "heimdall.test" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let path = request.url!.path
        let headers = path == "/advertised" ? ["Content-Length": "999"] : path == "/misleading" ? ["Content-Length": "1"] : [:]
        let status = path == "/error" ? 503 : 200
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data("1234".utf8))
        client?.urlProtocol(self, didLoad: Data((path == "/exact" ? "5678" : "56789").utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class DownloadLimitTests: XCTestCase {
    func fetch(_ path: String) async throws -> Data {
        let c = URLSessionConfiguration.ephemeral
        c.protocolClasses = [DownloadProtocol.self]
        return try await HTTP.send("https://heimdall.test/" + path, method: "GET", body: nil, headers: [:], maxBytes: 8, configuration: c)
    }
    func testExactLimitSucceeds() async throws {
        let data = try await fetch("exact")
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "12345678")
    }
    func testLimitsApplyWithMissingFalseOrLargeContentLength() async {
        for path in ["advertised", "chunked", "misleading"] {
            do { _ = try await fetch(path); XCTFail("accepted oversized " + path) }
            catch { XCTAssertEqual(error as? DownloadError, .tooLarge(8), path) }
        }
    }
    func testHTTPFailureIsNotAcceptedAsFeedData() async {
        do { _ = try await fetch("error"); XCTFail("accepted error response") }
        catch { XCTAssertEqual((error as? HTTPError)?.status, 503) }
    }
}
