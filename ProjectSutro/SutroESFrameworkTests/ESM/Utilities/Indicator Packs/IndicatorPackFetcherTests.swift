//
//  IndicatorPackFetcherTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/16/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - Fetching over HTTPS
/// Pins what the Security Extension's fetcher hands over from GitHub: the bytes and the status as they came, never
/// more than it's allowed to read, nothing over anything but HTTPS, and a failure when nothing answers. A URL
/// loading protocol answers in GitHub's place, so nothing leaves the Mac.
final class IndicatorPackFetcherTests: XCTestCase {
    private static let url = URL(string: "https://example.com/pack.json")!

    override func setUp() {
        super.setUp()
        AnsweringProtocol.reset()
    }

    /// Fetch a URL and wait for the answer.
    ///
    /// - Parameters:
    ///   - url: The URL.
    ///   - limit: The most bytes to read.
    /// - Returns: The answer.
    /// - Throws: If none comes.
    private func fetch(_ url: URL = IndicatorPackFetcherTests.url,
                       limit: Int = 1_000) throws -> FakePackFetcher.Answer {
        let fetcher = IndicatorPackFetcher(protocols: [AnsweringProtocol.self])
        return try awaitCallback(timeout: 15) { fetcher.fetch(url, limit: limit, completion: $0) }
    }

    /// What answered is handed over with its status, whatever the status is, up to exactly the limit.
    func testTheAnswerIsHandedOver() throws {
        AnsweringProtocol.answer(status: 200, chunks: [Data("hello ".utf8), Data("there".utf8)])
        let answer = try fetch().get()
        XCTAssertEqual(answer.status, 200)
        XCTAssertEqual(answer.data, Data("hello there".utf8))

        AnsweringProtocol.answer(status: 404, chunks: [Data(#"{"message": "Not Found"}"#.utf8)])
        XCTAssertEqual(try fetch().get().status, 404)

        AnsweringProtocol.answer(status: 200, chunks: [Data(count: 600), Data(count: 400)])
        XCTAssertEqual(try fetch(limit: 1_000).get().data.count, 1_000)
    }

    /// An answer longer than the limit fails, however it arrives, rather than be read whole.
    func testAnAnswerPastTheLimitFails() throws {
        for chunks in [[Data(count: 1_001)], [Data(count: 600), Data(count: 401)], [Data(count: 5_000_000)]] {
            AnsweringProtocol.answer(status: 200, chunks: chunks)
            XCTAssertEqual(thrown(IndicatorPackFetchError.self) { try self.fetch(limit: 1_000).get() }, .tooLarge)
        }
    }

    /// Anything but HTTPS fails without a request, and nothing answering is unreachable.
    func testOnlyHTTPSIsAsked() throws {
        AnsweringProtocol.answer(status: 200, chunks: [Data("hello".utf8)])
        for address in ["http://example.com/pack.json", "file:///etc/hosts", "ftp://example.com/pack.json"] {
            let refused = thrown(IndicatorPackFetchError.self) {
                try self.fetch(try XCTUnwrap(URL(string: address))).get()
            }
            guard case .unreachable? = refused else { return XCTFail("\(address) was fetched") }
        }
        XCTAssertEqual(AnsweringProtocol.asked, 0)

        AnsweringProtocol.reset()
        guard case .unreachable? = thrown(IndicatorPackFetchError.self, by: { try self.fetch().get() }) else {
            return XCTFail("Nothing answered, and it wasn't unreachable")
        }
        XCTAssertEqual(AnsweringProtocol.asked, 1)
    }
}


// MARK: - GitHub's place
/// Answers every request a session makes with what a test set, in the chunks it set, or fails when it set nothing.
private final class AnsweringProtocol: URLProtocol {
    private struct State {
        var answer: (status: Int, chunks: [Data])?
        var asked = 0
    }

    private static let state = OSAllocatedUnfairLock(initialState: State())

    /// How many requests were made.
    static var asked: Int {
        state.withLock { $0.asked }
    }

    /// Answer nothing, and forget what was asked.
    static func reset() {
        state.withLock { $0 = State() }
    }

    /// - Parameters:
    ///   - status: The HTTP status to answer.
    ///   - chunks: The body, in the pieces it arrives in.
    static func answer(status: Int, chunks: [Data]) {
        state.withLock { $0.answer = (status, chunks) }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        let answer = Self.state.withLock { state -> (status: Int, chunks: [Data])? in
            state.asked += 1
            return state.answer
        }
        guard let answer, let url = request.url,
              let response = HTTPURLResponse(url: url, statusCode: answer.status, httpVersion: "HTTP/1.1",
                                             headerFields: nil) else {
            client?.urlProtocol(self, didFailWithError: URLError(.notConnectedToInternet))
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        for chunk in answer.chunks { client?.urlProtocol(self, didLoad: chunk) }
        client?.urlProtocolDidFinishLoading(self)
    }
}
