//
//  MessageValueCacheTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Value cache
/// Pins ``MessageValueCache``: each field is read once per event, its values are ``MessageValues``', and a reset
/// starts the next event afresh.
final class MessageValueCacheTests: XCTestCase {
    /// Every field reads as ``MessageValues`` reads it, on every event of the synthetic corpus, through one cache.
    func testValuesAreMessageValues() throws {
        var cache = MessageValueCache()
        for message in try SyntheticCorpus.records().map(\.message) {
            cache.reset()
            for field in IndicatorField.allCases.reversed() {
                XCTAssertEqual(cache.value(of: field, in: message), MessageValues.value(of: field, in: message),
                               "\(message.es_event_type) \(field.path)")
            }
            XCTAssertEqual(cache.readCount, IndicatorField.allCases.count)
        }
    }

    /// A field asked for twice is read once: the second answer is the first's, even when the event it's given has
    /// changed, until a reset.
    func testReadsEachFieldOncePerEvent() throws {
        var message = try exec(commandLine: "first")
        var cache = MessageValueCache()
        XCTAssertEqual(cache.value(of: .execCommandLine, in: message), IndicatorValue("first"))
        message = try exec(commandLine: "second")
        XCTAssertEqual(cache.value(of: .execCommandLine, in: message), IndicatorValue("first"))
        XCTAssertEqual(cache.readCount, 1)
        cache.reset()
        XCTAssertEqual(cache.readCount, 0)
        XCTAssertEqual(cache.value(of: .execCommandLine, in: message), IndicatorValue("second"))
    }

    /// A reset forgets every field read, and only those: the next event's values are its own, `nil` ones included.
    func testResetForgetsTheLastEvent() throws {
        let exec = try exec(commandLine: "launchctl load")
        let close = try XCTUnwrap(SyntheticCorpus.records().map(\.message).first {
            $0.es_event_type == "ES_EVENT_TYPE_NOTIFY_CLOSE"
        })
        var cache = MessageValueCache()
        XCTAssertEqual(cache.value(of: .execCommandLine, in: exec), IndicatorValue("launchctl load"))
        XCTAssertFalse(cache.value(of: .esEventType, in: exec).isNull)
        cache.reset()
        XCTAssertEqual(cache.value(of: .execCommandLine, in: close), .null)
        XCTAssertEqual(cache.value(of: .esEventType, in: close), IndicatorValue("ES_EVENT_TYPE_NOTIFY_CLOSE"))
        XCTAssertEqual(cache.readCount, 2)
    }

    /// - Parameter commandLine: The command line.
    /// - Returns: The synthetic corpus's first exec, with that command line.
    /// - Throws: The error making up the corpus, or a failure when it has no exec.
    private func exec(commandLine: String) throws -> Message {
        var message = try XCTUnwrap(SyntheticCorpus.records().map(\.message).first {
            $0.es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC"
        })
        var exec = try XCTUnwrap(message.event.exec, "The corpus's first exec has no exec event")
        exec.command_line = commandLine
        message.event = .exec(exec)
        return message
    }
}
