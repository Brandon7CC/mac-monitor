//
//  MessageSerializerIndicatorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Stamping in the serializer
/// Pins the indicators a capture lane stamps on the events it builds: through `MessageSerializer.serializeEvent`, a
/// close, create, open and mmap carry the shipped indicators they match, the same ones Mac Monitor's own matching
/// finds, each the Security Extension's and with its indicator's severity, and none undetermined. An event that
/// matches none carries `[]`, and a lane without a set stamps nothing, so its records have no `indicators`. An event
/// the scan budget can't decide carries `indicators_undetermined`.
final class MessageSerializerIndicatorTests: XCTestCase {
    /// A plist written in a launch agents folder is "Plist modified".
    func testAModifiedCloseOfAPlist() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CLOSE)
        fixture.close("/Users/a/Library/LaunchAgents/com.example.agent.plist", modified: true)
        let message = try assertStamps(fixture, on: .file, including: "Plist modified")
        XCTAssertEqual(message.indicators?.hits.first?.severity, .low)
    }

    /// The same plist closed unwritten matches nothing, and says so with `[]`.
    func testAnUnmodifiedCloseMatchesNothing() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CLOSE)
        fixture.close("/Users/a/Library/LaunchAgents/com.example.agent.plist", modified: false)
        let (message, record) = try serialized(fixture, on: .file)
        XCTAssertEqual(message.indicators, IndicatorVerdicts([]))
        XCTAssertEqual((record["indicators"] as? [Any])?.count, 0)
        XCTAssertEqual(try matcherHits(message), [])
    }

    /// The image `NSCreateObjectFileImageFromMemory` makes is "Reflective loading", which is medium.
    func testACreateOfAReflectiveImage() throws {
        let image = try temporaryFile(containing: "", named: "NSCreateObjectFileImageFromMemory-x8Vq2b")
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CREATE)
        fixture.create(image.lastPathComponent, in: image.deletingLastPathComponent().path)
        let message = try assertStamps(fixture, on: .file, including: "Reflective loading")
        XCTAssertEqual(message.indicators?.hits.map(\.severity), [.medium])
    }

    /// A login keychain opened by a process that isn't a keychain daemon is "Keychain opened".
    func testAnOpenOfAKeychain() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OPEN)
        fixture.open("/Users/a/Library/Keychains/login.keychain-db")
        let message = try assertStamps(fixture, on: .file, including: "Keychain opened")
        XCTAssertEqual(message.indicators?.hits.map(\.severity), [.low])
    }

    /// The AppleScript component mapped is "AppleScript / JXA", on the memory lane.
    func testAnMmapOfAnOSAComponent() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_MMAP)
        fixture.mmap("/System/Library/Components/AppleScript.component/Contents/MacOS/AppleScript")
        try assertStamps(fixture, on: .memory, including: "AppleScript / JXA")
    }

    /// A lane without a set evaluates nothing: the event has no verdicts, and its JSON no `indicators`.
    func testALaneWithoutASetStampsNothing() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CLOSE)
        fixture.close("/Users/a/Library/LaunchAgents/com.example.agent.plist", modified: true)
        let (message, record) = try serialized(fixture, on: .file, indicators: nil)
        XCTAssertNil(message.indicators)
        XCTAssertNil(record["indicators"])
    }

    /// An indicator of someone's own is stamped as it is, unshipped, and the JSON names who evaluated it.
    func testAnOwnIndicatorIsStampedAsItIs() throws {
        let own = ownIndicator("Hosts read", #"es_event_type == "ES_EVENT_TYPE_NOTIFY_OPEN" AND "#
                               + #"target_path == "/private/etc/hosts""#, severity: .high)
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OPEN)
        fixture.open("/private/etc/hosts")
        let (message, record) = try serialized(fixture, on: .file, indicators: CompiledIndicators([own]))
        assertStamped(message.indicators, from: [own])
        XCTAssertEqual(message.indicators?.hits.map(\.id), [own.id])
        let entry = try XCTUnwrap((record["indicators"] as? [[String: Any]])?.first)
        XCTAssertEqual(entry["evaluated_by"] as? String, "security_extension")
        XCTAssertEqual(entry["severity"] as? String, "high")
        XCTAssertEqual(entry["default"] as? Bool, false)
        XCTAssertEqual(entry["name"] as? String, "Hosts read")
    }

    /// A close of a path that isn't ASCII, past Foundation's window, whose `ENDSWITH[c]` costs more than the other
    /// fields' pool has, lists the indicator as undetermined, by the scan budget, and not as a hit; a close the set
    /// decides lists none.
    func testAnUndecidedCloseListsItsIndicator() throws {
        let ends = ownIndicator("Ends", #"es_event_type == "ES_EVENT_TYPE_NOTIFY_CLOSE" AND "#
                                + #"target_path ENDSWITH[c] "needle""#)
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CLOSE)
        fixture.close("/tmp/\u{E9}" + String(repeating: "a", count: StringMatching.foundationLimit) + "needle",
                      modified: false)
        let (message, record) = try serialized(fixture, on: .file, indicators: CompiledIndicators([ends]))
        XCTAssertEqual(message.indicators, IndicatorVerdicts([]))
        let entries = try XCTUnwrap(message.indicators_undetermined).entries
        XCTAssertEqual(entries.map(\.hit.id), [ends.id])
        XCTAssertEqual(entries.map(\.reason), [.scanBudget])
        XCTAssertEqual(entries.first?.hit.evaluated_by, .securityExtension)
        let listed = try XCTUnwrap(record["indicators_undetermined"] as? [[String: Any]])
        XCTAssertEqual(listed.map { $0["reason"] as? String }, ["scan_budget"])
        XCTAssertEqual(listed.first?["name"] as? String, "Ends")

        let plain = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CLOSE)
        plain.close("/tmp/needle", modified: false)
        let (decided, decidedRecord) = try serialized(plain, on: .file, indicators: CompiledIndicators([ends]))
        XCTAssertEqual(decided.indicators?.hits.map(\.id), [ends.id])
        XCTAssertNil(decided.indicators_undetermined)
        XCTAssertNil(decidedRecord["indicators_undetermined"])
    }
}


// MARK: - Helpers
extension MessageSerializerIndicatorTests {
    /// Serialize a message on a lane with a set, and read the event back as Mac Monitor decodes it.
    ///
    /// - Parameters:
    ///   - fixture: The message.
    ///   - eventClass: The lane's class.
    ///   - indicators: The lane's set, the shipped indicators by default.
    /// - Returns: The decoded event, and its JSON object.
    /// - Throws: A failure when it isn't encoded, or the error decoding it.
    func serialized(_ fixture: RawMessageFixture, on eventClass: EventClass,
                    indicators: CompiledIndicators? = XCTestCase.shippedIndicators)
        throws -> (Message, [String: Any]) {
        let lane = LaneContext(eventClass: eventClass, sensorID: "SENSOR", encoder: StreamingJSONEncoder(),
                               indicators: indicators)
        let json = try XCTUnwrap(MessageSerializer(processPath: { _, _ in nil }).serialize(fixture.raw, in: lane))
        let record = try XCTUnwrap(try JSONSerialization.jsonObject(with: json) as? [String: Any])
        return (try JSONDecoder().decode(Message.self, from: json), record)
    }

    /// Check that a message's event is stamped with the shipped indicators Mac Monitor's matching finds, one of them
    /// the named one, each as its indicator says, and none undetermined.
    ///
    /// - Parameters:
    ///   - fixture: The message.
    ///   - eventClass: The lane's class.
    ///   - name: A shipped indicator it must match.
    ///   - line: The caller's line.
    /// - Returns: The decoded event.
    /// - Throws: The error serializing or storing it.
    @discardableResult
    func assertStamps(_ fixture: RawMessageFixture, on eventClass: EventClass, including name: String,
                      line: UInt = #line) throws -> Message {
        let (message, record) = try serialized(fixture, on: eventClass)
        XCTAssertNil(message.indicators_undetermined, line: line)
        XCTAssertNil(record["indicators_undetermined"], line: line)
        let ids = try XCTUnwrap(message.indicators, line: line).hits.map(\.id)
        XCTAssertTrue(ids.contains(try shippedID(name)), "\(ids)", line: line)
        XCTAssertEqual(ids, try matcherHits(message), line: line)
        assertStamped(message.indicators, line: line)
        return message
    }
}
