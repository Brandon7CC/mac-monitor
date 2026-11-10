//
//  XCTestCase+IndicatorEngine.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Mac Monitor's side of the indicator set
extension XCTestCase {
    /// User defaults of their own, removed when the test ends.
    ///
    /// - Returns: The defaults.
    func makeDefaults() -> UserDefaults {
        let suite = "\(type(of: self)).\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        addTeardownBlock { defaults.removePersistentDomain(forName: suite) }
        return defaults
    }

    /// A transport that takes requests to an indicator set as a caller with `access`, and replies on the main
    /// queue, as Mac Monitor's connection to the Security Extension does.
    ///
    /// - Parameters:
    ///   - set: The set, loaded.
    ///   - access: What the caller may do.
    /// - Returns: The transport.
    func transport(to set: SavedIndicatorSet, access: MuteAccess = .write) -> IndicatorEngine.Transport {
        { request, reply in
            set.handle(request, access: access, caller: "Test") { data in DispatchQueue.main.async { reply(data) } }
        }
    }

    /// Send a request through an engine and wait for its reply.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - engine: The engine.
    /// - Returns: The reply, or `nil` when there was none.
    @discardableResult
    func send(_ request: IndicatorRequest, through engine: IndicatorEngine) -> IndicatorReply? {
        let replied = expectation(description: "Reply to \(request.operation.rawValue)")
        var reply: IndicatorReply?
        engine.send(request) {
            reply = $0
            replied.fulfill()
        }
        wait(for: [replied], timeout: 10)
        return reply
    }
}
