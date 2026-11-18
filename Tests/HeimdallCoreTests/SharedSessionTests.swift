#if canImport(Network)
import Foundation
import Network
import XCTest
@testable import HeimdallCore

/// A real loopback server: no custom URLSessionConfiguration or URLProtocol, so every
/// request exercises HTTP.sharedSession and its task-ID delegate routing.
private final class ConcurrentHTTPServer: @unchecked Sendable {
    private let queue = DispatchQueue(label: "heimdall.shared-session-test-server")
    private let listener: NWListener
    private var connections: [NWConnection] = []
    private var waiting: [(NWConnection, String)] = []
    private var requests = 0
    private var peakWaiting = 0
    private let batchSize: Int

    init(batchSize: Int) throws {
        self.batchSize = batchSize
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
    }

    func start(ready: XCTestExpectation) {
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.fulfill() }
            if case .failed = state { ready.fulfill() }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { connection.cancel(); return }
            self.connections.append(connection)
            connection.start(queue: self.queue)
            self.readRequest(connection, buffer: Data())
        }
        listener.start(queue: queue)
        // Release the barrier on failure too, so a routing regression doesn't deadlock the suite.
        queue.asyncAfter(deadline: .now() + 5) { [weak self] in self?.releaseBatch() }
    }

    var port: UInt16? { listener.port?.rawValue }
    var concurrentRequests: Int { queue.sync { peakWaiting } }
    var requestCount: Int { queue.sync { requests } }

    func stop() {
        queue.sync {
            listener.cancel()
            for connection in connections { connection.cancel() }
            connections.removeAll()
            waiting.removeAll()
        }
    }

    private func readRequest(_ connection: NWConnection, buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, complete, error in
            guard let self else { return }
            let received = buffer + (data ?? Data())
            guard received.count <= 16_384 else { connection.cancel(); return }
            if let text = String(data: received, encoding: .utf8), text.contains("\r\n\r\n") {
                let path = text.split(separator: " ").dropFirst().first.map(String.init) ?? "/"
                self.requests += 1
                if self.requests <= self.batchSize {
                    self.waiting.append((connection, path))
                    self.peakWaiting = max(self.peakWaiting, self.waiting.count)
                    if self.waiting.count == self.batchSize { self.releaseBatch() }
                } else { self.respond(connection, path: path) }
            } else if !complete && error == nil {
                self.readRequest(connection, buffer: received)
            } else { connection.cancel() }
        }
    }

    private func releaseBatch() {
        let batch = waiting
        waiting.removeAll()
        for (connection, path) in batch { respond(connection, path: path) }
    }

    private func respond(_ connection: NWConnection, path: String) {
        if path == "/disconnect" { connection.cancel(); return }
        let status = path == "/error" ? "503 Service Unavailable" : "200 OK"
        let framing = path == "/advertised-limit" ? "Content-Length: 1024" : "Transfer-Encoding: chunked"
        let header = "HTTP/1.1 \(status)\r\n\(framing)\r\nX-Request: \(path)\r\nConnection: close\r\n\r\n"
        let body = path == "/large" || path == "/stream-limit" ? String(repeating: "x", count: 32) : "body:\(path)"
        let chunks = [String(body.prefix(body.count / 2)), String(body.suffix(body.count - body.count / 2))]
        let frames = chunks.map { "\(String($0.utf8.count, radix: 16))\r\n\($0)\r\n" } + ["0\r\n\r\n"]
        let payload = path == "/advertised-limit" ? [Data(repeating: 120, count: 1024)] : frames.map { Data($0.utf8) }
        send([Data(header.utf8)] + payload, on: connection)
    }

    private func send(_ frames: [Data], on connection: NWConnection) {
        guard let first = frames.first else { connection.cancel(); return }
        connection.send(content: first, completion: .contentProcessed { [weak self] error in
            if error != nil { connection.cancel() }
            else { self?.send(Array(frames.dropFirst()), on: connection) }
        })
    }
}

final class SharedSessionTests: XCTestCase {
    private struct Result: Sendable {
        var path: String
        var data: Data?
        var requestHeader: String?
        var status: Int?
        var limit: Int?
    }

    func testConcurrentSharedSessionRoutesBodiesErrorsAndLimitsIndependently() async throws {
        let server = try ConcurrentHTTPServer(batchSize: 5)
        defer { server.stop() }
        let ready = expectation(description: "Loopback listener ready")
        server.start(ready: ready)
        await fulfillment(of: [ready], timeout: 5)
        let port = try XCTUnwrap(server.port)
        let base = "http://127.0.0.1:\(port)"
        let requests = [("/small", 64), ("/large", 64), ("/stream-limit", 8), ("/advertised-limit", 8), ("/error", 64)]
        let results = await withTaskGroup(of: Result.self, returning: [Result].self) { group in
            for (path, limit) in requests {
                group.addTask {
                    do {
                        let (data, response) = try await HTTP.getWithResponse(base + path, maxBytes: limit)
                        return Result(path: path, data: data, requestHeader: response?.value(forHTTPHeaderField: "X-Request"), status: response?.statusCode)
                    } catch let error as DownloadError {
                        if case .tooLarge(let cap) = error { return Result(path: path, limit: cap) }
                    } catch let error as HTTPError {
                        return Result(path: path, status: error.status)
                    } catch { XCTFail("Unexpected error for \(path): \(error)") }
                    return Result(path: path)
                }
            }
            var results: [Result] = []
            for await result in group { results.append(result) }
            return results
        }
        XCTAssertEqual(server.concurrentRequests, 5, "All five requests must overlap before responses begin")
        XCTAssertEqual(results.count, 5)
        for path in ["/small", "/large"] {
            let result = try XCTUnwrap(results.first { $0.path == path })
            XCTAssertEqual(result.status, 200)
            XCTAssertEqual(result.requestHeader, path, "Response metadata must reach the correct receiver")
            XCTAssertEqual(result.data, Data((path == "/large" ? String(repeating: "x", count: 32) : "body:/small").utf8))
        }
        for path in ["/stream-limit", "/advertised-limit"] {
            let result = try XCTUnwrap(results.first { $0.path == path })
            XCTAssertEqual(result.limit, 8, path)
            XCTAssertNil(result.data)
        }
        XCTAssertEqual(results.first { $0.path == "/error" }?.status, 503)
        XCTAssertNil(results.first { $0.path == "/error" }?.data)

        // Cancelling oversized tasks and completing failed tasks must not invalidate the
        // shared session or leave a receiver that captures the next task's callbacks.
        let (data, response) = try await HTTP.getWithResponse(base + "/after-failures")
        XCTAssertEqual(data, Data("body:/after-failures".utf8))
        XCTAssertEqual(response?.value(forHTTPHeaderField: "X-Request"), "/after-failures")
        XCTAssertEqual(server.requestCount, 6)
    }

    func testTransportFailureDoesNotInterruptConcurrentOrSubsequentRequests() async throws {
        let server = try ConcurrentHTTPServer(batchSize: 2)
        defer { server.stop() }
        let ready = expectation(description: "Loopback listener ready")
        server.start(ready: ready)
        await fulfillment(of: [ready], timeout: 5)
        let base = "http://127.0.0.1:\(try XCTUnwrap(server.port))"
        async let healthy = HTTP.get(base + "/healthy")
        do {
            _ = try await HTTP.get(base + "/disconnect")
            XCTFail("A disconnected request must fail")
        } catch {
            XCTAssertEqual((error as NSError).domain, NSURLErrorDomain)
        }
        let body = try await healthy
        XCTAssertEqual(body, Data("body:/healthy".utf8))
        XCTAssertEqual(server.concurrentRequests, 2)
        let next = try await HTTP.get(base + "/recovered")
        XCTAssertEqual(next, Data("body:/recovered".utf8))
    }

}
#endif
