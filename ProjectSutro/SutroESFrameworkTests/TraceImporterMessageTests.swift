//
//  TraceImporterMessageTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Reading one event
/// Pins how ``TraceImporter/message(from:)`` reads one event from eslogger's JSON and from a Mac Monitor 2.1 export,
/// and which records it turns away. Nothing here opens the event store.
final class TraceImporterMessageTests: XCTestCase {
    /// eslogger's exit event: JSON Lines, slashes escaped, no Mac Monitor fields.
    private static let esloggerExit = "eslogger-exit.jsonl"
    /// eslogger's open event.
    private static let esloggerOpen = "eslogger-open.jsonl"
    /// Mac Monitor 2.1's export of an exit event: local time to the millisecond, lowercase cdhash, its own fields.
    private static let macMonitor21Exit = "macmonitor-2.1-exit.jsonl"
    /// When the eslogger exit event happened: its `time`, 2026-10-04T00:01:55.281215406Z.
    private static let esloggerExitDate = ProcessHelpers.timespecToTimestamp(
        timespec: timespec(tv_sec: 1_791_072_115, tv_nsec: 281_215_406))
    
    /// The event in a JSON object, read as the importer reads it.
    ///
    /// - Parameter object: The record.
    /// - Returns: The event.
    /// - Throws: The error ``TraceImporter/message(from:)`` throws.
    private func message(from object: Any) throws -> Message {
        try TraceImporter.message(from: try JSONSerialization.data(withJSONObject: object))
    }
    
    /// Assert that reading `json` throws a `TraceImportError` that `matches` accepts.
    ///
    /// - Parameters:
    ///   - json: The record's text.
    ///   - expected: Describes the error expected, for the failure message.
    ///   - matches: Decides whether the error is the one expected.
    ///   - line: The caller's line.
    private func assertRejects(_ json: String, _ expected: String, line: UInt = #line,
                               where matches: (TraceImportError) -> Bool) {
        XCTAssertThrowsError(try TraceImporter.message(from: Data(json.utf8)), line: line) { error in
            guard let error = error as? TraceImportError, matches(error) else {
                return XCTFail("Expected \(expected), got \(error)", line: line)
            }
        }
    }
    
    /// Is the error ``TraceImportError/notAnEvent``?
    ///
    /// - Parameter error: The error thrown.
    /// - Returns: Whether it's the one expected.
    private static func isNotAnEvent(_ error: TraceImportError) -> Bool {
        if case .notAnEvent = error { true } else { false }
    }
    
    // MARK: eslogger
    
    /// eslogger's Endpoint Security fields are read as written.
    ///
    /// - Throws: The error reading the fixture, or decoding an event that should decode.
    func testEsloggerExit() throws {
        let message = try TraceImporter.message(from: try fixture(Self.esloggerExit))
        guard case .exit(let exit) = message.event else { return XCTFail("Expected an exit event: \(message.event)") }
        XCTAssertEqual(exit.stat, 9)
        XCTAssertEqual(message.event_type, 15)
        XCTAssertEqual(message.version, 10)
        XCTAssertEqual(message.schema_version, 1)
        XCTAssertEqual(message.seq_num, 0)
        XCTAssertEqual(message.global_seq_num, 7)
        XCTAssertEqual(message.mach_time, 1_000_000_001)
        XCTAssertEqual(message.thread?.thread_id, 900_001)
        XCTAssertEqual(message.process.executable?.path, "/usr/libexec/exampled")
        XCTAssertEqual(message.process.cdhash, "00112233445566778899AABBCCDDEEFF01234567")
        XCTAssertEqual(message.process.signing_id, "com.example.exampled")
        XCTAssertNil(message.process.team_id)
        XCTAssertNil(message.process.tty)
    }
    
    /// eslogger's `time` is kept, and `message_darwin_time` is read from it to the nanosecond.
    ///
    /// - Throws: The error reading the fixture, or decoding an event that should decode.
    func testEsloggerTimeIsKeptAndRead() throws {
        let message = try TraceImporter.message(from: try fixture(Self.esloggerExit))
        XCTAssertEqual(message.time, "2026-10-04T00:01:55.281215406Z")
        XCTAssertEqual(message.message_darwin_time, Self.esloggerExitDate)
    }
    
    /// eslogger doesn't write Mac Monitor's fields: they're derived the way the Security Extension derives them.
    ///
    /// - Throws: The error reading the fixture, or decoding an event that should decode.
    func testEsloggerEventIsEnriched() throws {
        let message = try TraceImporter.message(from: try fixture(Self.esloggerExit))
        XCTAssertEqual(message.es_event_type, "ES_EVENT_TYPE_NOTIFY_EXIT")
        XCTAssertEqual(message.action_type_string, "ES_ACTION_TYPE_NOTIFY")
        XCTAssertEqual(message.context, "exampled")
        XCTAssertEqual(message.target_path, "/usr/libexec/exampled")
        XCTAssertEqual(message.process.pid, 4242)
        XCTAssertEqual(message.process.audit_token_string,
                       "pid:4242, euid:0, ruid:0, rgid:0, egid:0, asid:100001, auid:4294967295, pidversion:4243")
        XCTAssertEqual(message.process.euid, 0)
        XCTAssertEqual(message.process.euid_human, "root")
        XCTAssertEqual(message.process.codesigning_type, .platform)
        XCTAssertEqual(message.process.cs_validation_category_string, "ES_CS_VALIDATION_CATEGORY_PLATFORM")
    }
    
    /// An event's own file is read, its stat times included, and becomes its context and target path.
    ///
    /// - Throws: The error reading the fixture, or decoding an event that should decode.
    func testEsloggerOpen() throws {
        let message = try TraceImporter.message(from: try fixture(Self.esloggerOpen))
        guard case .open(let open) = message.event else { return XCTFail("Expected an open event: \(message.event)") }
        XCTAssertEqual(open.fflag, 1)
        XCTAssertEqual(open.file.path, "/private/tmp/example/report.txt")
        XCTAssertEqual(open.file.stat.st_ino, 2002)
        XCTAssertEqual(open.file.stat.st_mtimespec.tv_sec, 1_791_072_102)
        XCTAssertEqual(open.file.stat.st_mtimespec.tv_nsec, 772_525_676)
        XCTAssertEqual(message.es_event_type, "ES_EVENT_TYPE_NOTIFY_OPEN")
        XCTAssertEqual(message.context, "/private/tmp/example/report.txt")
        XCTAssertEqual(message.target_path, "/private/tmp/example/report.txt")
    }
    
    /// eslogger `--oslog` events read back with `log show --style json` carry the event as their `eventMessage`.
    ///
    /// - Throws: The error reading the fixture, or decoding an event that should decode.
    func testUnifiedLogEntry() throws {
        let event = String(decoding: try fixture(Self.esloggerExit), as: UTF8.self)
        let entry = ["timestamp": "2026-10-04 00:01:55.281", "eventMessage": "eslogger: " + event]
        let message = try self.message(from: entry)
        guard case .exit = message.event else { return XCTFail("Expected an exit event: \(message.event)") }
        XCTAssertEqual(message.time, "2026-10-04T00:01:55.281215406Z")
    }
    
    // MARK: Security Extension time
    
    /// The Security Extension's own `Message` carries `message_darwin_time` (seconds since 2001), which is used as is.
    ///
    /// - Throws: The error reading the fixture, or decoding an event that should decode.
    func testWireDarwinTimeIsUsed() throws {
        var object = try fixtureObject(Self.esloggerExit)
        object["message_darwin_time"] = 812_764_915.25
        let message = try self.message(from: object)
        XCTAssertEqual(message.message_darwin_time, Date(timeIntervalSinceReferenceDate: 812_764_915.25))
        XCTAssertEqual(message.time, "2026-10-04T00:01:55.281215406Z")
    }
    
    /// A `message_darwin_time` that isn't a time (more than about 3,000 years from 2001) is read from `time` instead.
    ///
    /// - Throws: The error reading the fixture, or decoding an event that should decode.
    func testDarwinTimeThatIsNoTimeFallsBackToTime() throws {
        var object = try fixtureObject(Self.esloggerExit)
        object["message_darwin_time"] = 1e12
        let message = try self.message(from: object)
        XCTAssertEqual(message.message_darwin_time, Self.esloggerExitDate)
    }
    
    // MARK: Mac Monitor 2.1
    
    /// A 2.1 export names its event, so its own fields are read as written rather than derived.
    ///
    /// - Throws: The error reading the fixture, or decoding an event that should decode.
    func testMacMonitor21KeepsItsOwnFields() throws {
        let message = try TraceImporter.message(from: try fixture(Self.macMonitor21Exit))
        guard case .exit(let exit) = message.event else { return XCTFail("Expected an exit event: \(message.event)") }
        XCTAssertEqual(exit.stat, 9)
        XCTAssertEqual(message.es_event_type, "ES_EVENT_TYPE_NOTIFY_EXIT")
        XCTAssertEqual(message.action_type_string, "ES_ACTION_TYPE_NOTIFY")
        XCTAssertEqual(message.context, "exampled")
        XCTAssertEqual(message.target_path, "/usr/libexec/exampled")
        XCTAssertEqual(message.macOS, "26.0 (Build 25A000)")
        XCTAssertEqual(message.sensor_id, "SYNTHETIC-SENSOR-ID")
        XCTAssertEqual(message.process.pid, 4444)
        XCTAssertEqual(message.process.euid_human, "root")
        XCTAssertEqual(message.process.codesigning_type, .platform)
        /// Hashes are kept as the file wrote them: 2.1 wrote them in lowercase.
        XCTAssertEqual(message.process.cdhash, "00112233445566778899aabbccddeeff01234567")
    }
    
    /// 2.1 wrote local time to the millisecond with a literal `Z`: it's read in this Mac's time zone with the formatter
    /// that wrote it, and `time` is rebuilt in eslogger's format from the result.
    ///
    /// - Throws: The error reading the fixture, or decoding an event that should decode.
    func testMacMonitor21TimeIsLocalTime() throws {
        let legacy = "2026-10-03T17:01:57.289Z"
        let written = try XCTUnwrap(ProcessHelpers.timestampFormatter.date(from: legacy))
        let message = try TraceImporter.message(from: try fixture(Self.macMonitor21Exit))
        XCTAssertEqual(message.message_darwin_time.timeIntervalSince1970, written.timeIntervalSince1970, accuracy: 1e-6)
        /// Minutes and seconds don't depend on the time zone, nor does the fraction, rounded to the microsecond.
        XCTAssertTrue(ESLogger.isESLoggerTime(message.time), message.time)
        XCTAssertTrue(message.time.hasSuffix("57.289000000Z"), message.time)
    }
    
    // MARK: Records that aren't events
    
    /// JSON without an `event` and a `process` object isn't an event.
    func testOtherJSONIsNotAnEvent() {
        assertRejects(#"{"foo":1}"#, "notAnEvent", where: Self.isNotAnEvent)
        assertRejects(#"[{"event":{},"process":{}}]"#, "notAnEvent", where: Self.isNotAnEvent)
        assertRejects(#"{"event":"exit","process":{}}"#, "notAnEvent", where: Self.isNotAnEvent)
    }
    
    /// An event of a type Mac Monitor doesn't have is counted by eslogger's name for it.
    func testUnsupportedEventIsNamed() {
        assertRejects(#"{"event":{"bogus":{}},"process":{}}"#, "unsupportedEvent(bogus)") {
            if case .unsupportedEvent("bogus") = $0 { true } else { false }
        }
    }
    
    /// An event without a type isn't shown.
    func testEventWithoutTypeIsIncomplete() {
        assertRejects(#"{"event":{},"process":{}}"#, "incomplete(no event type)") {
            if case .incomplete("no event type") = $0 { true } else { false }
        }
    }
    
    /// An event without a time it can be read from isn't shown.
    ///
    /// - Throws: The error reading the fixture, or decoding an event that should decode.
    func testEventWithoutTimeIsIncomplete() throws {
        var object = try fixtureObject(Self.esloggerExit)
        object["time"] = nil
        let json = String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self)
        assertRejects(json, "incomplete(no time)") { if case .incomplete("no time") = $0 { true } else { false } }
    }
    
    /// The summary that ends `log show --style ndjson` isn't an event, and isn't a problem either.
    func testLogTrailer() {
        assertRejects(#"{"count":2,"finished":1}"#, "logTrailer") { if case .logTrailer = $0 { true } else { false } }
    }
    
    /// Text that isn't JSON is an error.
    func testMalformedJSONThrows() {
        XCTAssertThrowsError(try TraceImporter.message(from: Data(#"{"event":{"exit":"#.utf8)))
    }
}
