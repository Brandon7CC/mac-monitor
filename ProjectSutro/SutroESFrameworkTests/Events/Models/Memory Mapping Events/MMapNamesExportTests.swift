//
//  MMapNamesExportTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - mmap names in the export
/// Pins that every exported mmap has `protection_names`, `max_protection_names` and `flag_names` beside the raw
/// integers, derived when it's written: an event the Security Extension captures, eslogger's record, a record Mac
/// Monitor 3.0.0 exported without them, and a 3.0.0 Security Extension's message, which has no names on the wire.
final class MMapNamesExportTests: XCTestCase {
    /// The mapped file's path.
    private static let path = "/usr/lib/libexample.dylib"
    /// The test's protection: `PROT_READ | PROT_EXEC`.
    private static let protection: Int32 = 5
    /// The test's max protection: every `PROT_*` bit, and `VM_PROT_STRIP_READ` (0x80), which has no `PROT_*` name.
    private static let maxProtection: Int32 = 0x87
    /// The test's flags: `MAP_PRIVATE | MAP_FIXED`, and bit 0x10000, which `<sys/mman.h>` doesn't name.
    private static let flags: Int32 = 0x1_0012

    /// An mmap as the Security Extension captures it.
    ///
    /// - Returns: The event.
    private func captured() -> Message {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_MMAP)
        fixture.message.pointee.event.mmap.source = fixture.file(Self.path)
        fixture.message.pointee.event.mmap.protection = Self.protection
        fixture.message.pointee.event.mmap.max_protection = Self.maxProtection
        fixture.message.pointee.event.mmap.flags = Self.flags
        return Message(from: fixture.raw)
    }

    /// The mmap object a record has, as eslogger and Mac Monitor 3.0.0 write it: without names.
    ///
    /// - Returns: The object.
    /// - Throws: The error reading the open fixture.
    private func mmapObject() throws -> [String: Any] {
        let open = try XCTUnwrap(try fixtureObject("eslogger-open.jsonl")["event"] as? [String: Any])
        let file = try XCTUnwrap((open["open"] as? [String: Any])?["file"])
        return ["protection": Self.protection, "max_protection": Self.maxProtection, "flags": Self.flags,
                "file_pos": 0, "source": file]
    }

    /// A record exported by Mac Monitor 3.0.0: Mac Monitor's own record (with `es_event_type`, so it's not enriched
    /// when it's opened), at telemetry 1.0.0, without the names.
    ///
    /// - Returns: The record.
    /// - Throws: The error reading a fixture.
    private func macMonitor300Record() throws -> [String: Any] {
        var record = try legacyRecord(ES_EVENT_TYPE_NOTIFY_MMAP, try mmapObject())
        record[TelemetrySchema.versionKey] = "1.0.0"
        return record
    }

    /// Assert that an export's mmap has the test's names beside its raw integers.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - label: Which event it is.
    ///   - line: The caller's line.
    /// - Throws: An `XCTest` failure if the export has no mmap.
    private func assertNamed(_ message: Message, _ label: String, line: UInt = #line) throws {
        let mmap = try event("mmap", in: try export(message))
        XCTAssertEqual(mmap["protection_names"] as? [String], ["PROT_READ", "PROT_EXEC"], label, line: line)
        XCTAssertEqual(mmap["max_protection_names"] as? [String], ["PROT_READ", "PROT_WRITE", "PROT_EXEC"], label,
                       line: line)
        XCTAssertEqual(mmap["flag_names"] as? [String], ["MAP_PRIVATE", "MAP_FIXED"], label, line: line)
        XCTAssertEqual(mmap["protection"] as? Int, Int(Self.protection), label, line: line)
        XCTAssertEqual(mmap["max_protection"] as? Int, Int(Self.maxProtection), label, line: line)
        XCTAssertEqual(mmap["flags"] as? Int, Int(Self.flags), label, line: line)
    }

    // MARK: Exports

    /// A captured mmap exports the names, and the raw integers keep the bits that have none.
    func testCapturedMapIsNamed() throws {
        try assertNamed(captured(), "captured")
    }

    /// eslogger's record, opened, exports the names.
    func testESLoggerMapIsNamed() throws {
        try assertNamed(try importRecord(try esloggerRecord(ES_EVENT_TYPE_NOTIFY_MMAP, try mmapObject())), "eslogger")
    }

    /// A record Mac Monitor 3.0.0 exported without the names exports them when it's opened.
    func testMacMonitor300MapIsNamed() throws {
        try assertNamed(try importRecord(try macMonitor300Record()), "3.0.0")
    }

    /// The names aren't on the wire, so a 3.0.0 Security Extension's message is the same: it decodes, and its
    /// export has them.
    func testWireMessageWithoutNamesIsNamed() throws {
        let json = try wire(captured())
        let text = String(decoding: json, as: UTF8.self)
        for key in ["protection_names", "max_protection_names", "flag_names"] {
            XCTAssertFalse(text.contains("\"\(key)\""), key)
        }
        try assertNamed(try JSONDecoder().decode(Message.self, from: json), "wire")
    }

    /// A protection of 0 exports `PROT_NONE`, and flags of 0 export no names (`MAP_FILE` is never named).
    func testZeroValues() throws {
        var object = try mmapObject()
        object["protection"] = 0
        object["max_protection"] = 0
        object["flags"] = 0
        let mmap = try event("mmap", in: try export(try importRecord(try esloggerRecord(ES_EVENT_TYPE_NOTIFY_MMAP,
                                                                                      object))))
        XCTAssertEqual(mmap["protection_names"] as? [String], ["PROT_NONE"])
        XCTAssertEqual(mmap["max_protection_names"] as? [String], ["PROT_NONE"])
        XCTAssertEqual(mmap["flag_names"] as? [String], [])
    }

    /// The event list's context is still the mapped file's path.
    func testContextIsThePath() {
        XCTAssertEqual(captured().context, Self.path)
    }

    /// Predicates can use the names, as searches and `macmonitor stream --predicate` do.
    func testPredicatesUseTheNames() throws {
        let record = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(exportText(captured()).utf8))
                                   as? NSDictionary)
        let matching = ["ANY event.mmap.protection_names == 'PROT_EXEC'",
                        "ANY event.mmap.max_protection_names == 'PROT_WRITE'",
                        "ANY event.mmap.flag_names == 'MAP_FIXED'"]
        for source in matching {
            XCTAssertTrue(try StreamFilter.Predicate(source).evaluate(on: record), source)
        }
        XCTAssertFalse(try StreamFilter.Predicate("ANY event.mmap.protection_names == 'PROT_WRITE'")
            .evaluate(on: record))
    }
    
    // MARK: Schema

    /// Each export follows the telemetry schema, with the names.
    func testExportsFollowSchema() throws {
        let exports = [("captured", captured()),
                       ("eslogger", try importRecord(try esloggerRecord(ES_EVENT_TYPE_NOTIFY_MMAP, try mmapObject()))),
                       ("3.0.0", try importRecord(try macMonitor300Record()))]
        assertValid(exports.map { ($0.0, exportText($0.1)) }, with: try generatedValidator())
    }
}
