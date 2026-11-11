//
//  SetModeNamesExportTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - setmode names in the export
/// Pins that every exported setmode has `mode_symbolic`, `previous_mode` and `mode_added` beside the raw `mode`,
/// derived when it's written from the mode and the target's stat: an event the Security Extension captures, eslogger's
/// record, a record Mac Monitor 3.0.0 exported without them, and a 3.0.0 Security Extension's message, which has none
/// on the wire.
final class SetModeNamesExportTests: XCTestCase {
    /// The target's path.
    private static let path = "/Users/Shared/payload"
    /// The target's `st_mode` before the change: a regular file, `rw-r--r--`.
    private static let previousStatMode: Int = 0o100644
    /// The mode the file is given: setuid and execute, `rwsr-xr-x`.
    private static let mode: Int32 = 0o4755

    /// A setmode as the Security Extension captures it.
    ///
    /// - Parameter statMode: The target's `st_mode`, 0 for a target with no stat.
    /// - Returns: The event.
    private func captured(statMode: Int = previousStatMode) -> Message {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_SETMODE)
        let target = fixture.file(Self.path)
        target.pointee.stat.st_mode = mode_t(statMode)
        fixture.message.pointee.event.setmode.target = target
        fixture.message.pointee.event.setmode.mode = mode_t(Self.mode)
        return Message(from: fixture.raw)
    }

    /// The setmode object a record has, as eslogger and Mac Monitor 3.0.0 write it: without the names.
    ///
    /// - Returns: The object.
    /// - Throws: The error reading the open fixture.
    private func setmodeObject() throws -> [String: Any] {
        let open = try XCTUnwrap(try fixtureObject("eslogger-open.jsonl")["event"] as? [String: Any])
        var file = try XCTUnwrap((open["open"] as? [String: Any])?["file"] as? [String: Any])
        var stat = try XCTUnwrap(file["stat"] as? [String: Any])
        stat["st_mode"] = Self.previousStatMode
        file["stat"] = stat
        return ["mode": Self.mode, "target": file]
    }

    /// A record exported by Mac Monitor 3.0.0: Mac Monitor's own record, at telemetry 1.0.0, without the names.
    ///
    /// - Returns: The record.
    /// - Throws: The error reading a fixture.
    private func macMonitor300Record() throws -> [String: Any] {
        var record = try legacyRecord(ES_EVENT_TYPE_NOTIFY_SETMODE, try setmodeObject())
        record[TelemetrySchema.versionKey] = "1.0.0"
        return record
    }

    /// Assert that an export's setmode has the test's names beside its raw mode.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - label: Which event it is.
    ///   - line: The caller's line.
    /// - Throws: An `XCTest` failure if the export has no setmode.
    private func assertNamed(_ message: Message, _ label: String, line: UInt = #line) throws {
        let setmode = try event("setmode", in: try export(message))
        XCTAssertEqual(setmode["mode"] as? Int, Int(Self.mode), label, line: line)
        XCTAssertEqual(setmode["mode_symbolic"] as? String, "rwsr-xr-x", label, line: line)
        XCTAssertEqual(setmode["previous_mode"] as? Int, 0o644, label, line: line)
        XCTAssertEqual(setmode["mode_added"] as? [String], ["executable", "setuid"], label, line: line)
    }

    // MARK: Exports

    /// A captured setmode exports the names.
    func testCapturedModeIsNamed() throws {
        try assertNamed(captured(), "captured")
    }

    /// eslogger's record, opened, exports the names.
    func testESLoggerModeIsNamed() throws {
        try assertNamed(try importRecord(try esloggerRecord(ES_EVENT_TYPE_NOTIFY_SETMODE, try setmodeObject())),
                        "eslogger")
    }

    /// A record Mac Monitor 3.0.0 exported without the names exports them when it's opened.
    func testMacMonitor300ModeIsNamed() throws {
        try assertNamed(try importRecord(try macMonitor300Record()), "3.0.0")
    }

    /// The names aren't on the wire, so a 3.0.0 Security Extension's message is the same: it decodes, and its
    /// export has them.
    func testWireMessageWithoutNamesIsNamed() throws {
        let json = try wire(captured())
        let text = String(decoding: json, as: UTF8.self)
        for key in ["mode_symbolic", "previous_mode", "mode_added"] {
            XCTAssertFalse(text.contains("\"\(key)\""), key)
        }
        try assertNamed(try JSONDecoder().decode(Message.self, from: json), "wire")
    }

    /// Without a stat, `previous_mode` is written as `null` and every bit the mode sets counts as added.
    func testWithoutAStatEveryBitCounts() throws {
        let setmode = try event("setmode", in: try export(captured(statMode: 0)))
        XCTAssertTrue(setmode.keys.contains("previous_mode"))
        XCTAssertTrue(setmode["previous_mode"] is NSNull)
        XCTAssertEqual(setmode["mode_added"] as? [String], ["executable", "setuid"])
    }

    /// The Event Facts and the export read the same values.
    func testEventFactsAndExportAgree() throws {
        try withStoredEvent(captured()) { message in
            let stored = try XCTUnwrap(message.event.setmode)
            XCTAssertEqual(stored.fileMode.symbolic, "rwsr-xr-x")
            XCTAssertEqual(stored.previousFileMode?.permissions, 0o644)
            XCTAssertEqual(stored.addedCallouts, [.madeExecutable, .setuidAdded])
        }
    }

    /// Predicates can use the names, as searches and `macmonitor stream --predicate` do.
    func testPredicatesUseTheNames() throws {
        let record = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(exportText(captured()).utf8))
                                   as? NSDictionary)
        let matching = ["ANY event.setmode.mode_added == 'executable'",
                        "event.setmode.mode_symbolic BEGINSWITH 'rws'",
                        "event.setmode.previous_mode == 420"]
        for source in matching {
            XCTAssertTrue(try StreamFilter.Predicate(source).evaluate(on: record), source)
        }
        XCTAssertFalse(try StreamFilter.Predicate("ANY event.setmode.mode_added == 'world_writable'")
            .evaluate(on: record))
    }

    // MARK: Schema

    /// Each export follows the telemetry schema, with the names.
    func testExportsFollowSchema() throws {
        let exports = [("captured", captured()),
                       ("no stat", captured(statMode: 0)),
                       ("eslogger", try importRecord(try esloggerRecord(ES_EVENT_TYPE_NOTIFY_SETMODE,
                                                                        try setmodeObject()))),
                       ("3.0.0", try importRecord(try macMonitor300Record()))]
        assertValid(exports.map { ($0.0, exportText($0.1)) }, with: try generatedValidator())
    }
}
