//
//  FileTypeExportTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
import EndpointSecurity
import MachO
@testable import SutroESFramework


// MARK: - File types from capture to export
/// Pins `file_type` and `mach_o_type` on mmap and close events from capture to export: a capture lane reads an mmap's
/// file and a modified close's (never an unmodified close's), the event store keeps both values, the export always
/// writes both keys and follows the schema, the wire carries them, a 3.0.0 Security Extension's message and a trace
/// without them decode with none, opening a trace never reads the disk, and predicates can use them.
final class FileTypeExportTests: XCTestCase {
    /// A message whose event names a real file, with its real stat, as Endpoint Security names one.
    ///
    /// - Parameters:
    ///   - type: `ES_EVENT_TYPE_NOTIFY_MMAP` or `ES_EVENT_TYPE_NOTIFY_CLOSE`.
    ///   - path: The file.
    ///   - modified: A close's `modified`.
    /// - Returns: The message's fixture.
    /// - Throws: The error from `stat`.
    private func rawEvent(_ type: es_event_type_t, _ path: String, modified: Bool = true) throws -> RawMessageFixture {
        let fixture = rawMessage(type: type)
        let info = try fileStat(path)
        if type == ES_EVENT_TYPE_NOTIFY_MMAP {
            fixture.mmap(path)
            fixture.message.pointee.event.mmap.source.pointee.stat = info
        } else {
            fixture.close(path, modified: modified)
            fixture.message.pointee.event.close.target.pointee.stat = info
        }
        return fixture
    }

    /// An event serialized as a capture lane serializes it, and decoded from the wire.
    ///
    /// - Parameters:
    ///   - fixture: The raw message.
    ///   - lane: The capture lane, a new one by default.
    /// - Returns: The event.
    /// - Throws: An `XCTest` failure if it isn't serialized, or the error decoding it.
    private func captured(_ fixture: RawMessageFixture,
                          in lane: LaneContext = LaneContext(eventClass: .file, sensorID: "SENSOR",
                                                             encoder: StreamingJSONEncoder())) throws -> Message {
        let json = try XCTUnwrap(MessageSerializer().serialize(fixture.raw, in: lane))
        return try JSONDecoder().decode(Message.self, from: json)
    }

    /// A dylib in a temporary folder.
    ///
    /// - Returns: Its path.
    /// - Throws: The error writing it.
    private func dylib() throws -> String {
        try temporaryFile(bytes: FileTypeSamples.machO(MH_DYLIB), named: "libsample.dylib")
    }

    // MARK: Capture

    /// An mmap's file is read: a dylib's type and file type, and a script's type without one.
    func testCapturedMMap() throws {
        let mapped = try captured(try rawEvent(ES_EVENT_TYPE_NOTIFY_MMAP, try dylib()))
        XCTAssertEqual(mapped.event.mmap?.file_type, "com.apple.mach-o-dylib")
        XCTAssertEqual(mapped.event.mmap?.mach_o_type, "MH_DYLIB")
        let script = try temporaryFile(bytes: FileTypeSamples.text("#!/usr/bin/env python3\n"))
        let mappedScript = try captured(try rawEvent(ES_EVENT_TYPE_NOTIFY_MMAP, script))
        XCTAssertEqual(mappedScript.event.mmap?.file_type, "public.python-script")
        XCTAssertNil(mappedScript.event.mmap?.mach_o_type)
    }

    /// The lane's memory answers the next mmap of the file: deleted since, it still has its type.
    func testCapturedMMapIsRemembered() throws {
        let lane = LaneContext(eventClass: .file, sensorID: "SENSOR", encoder: StreamingJSONEncoder())
        let path = try dylib()
        let fixture = try rawEvent(ES_EVENT_TYPE_NOTIFY_MMAP, path)
        XCTAssertEqual(try captured(fixture, in: lane).event.mmap?.mach_o_type, "MH_DYLIB")
        unlink(path)
        XCTAssertEqual(try captured(fixture, in: lane).event.mmap?.mach_o_type, "MH_DYLIB")
        XCTAssertNil(try captured(fixture).event.mmap?.file_type, "A new lane reads the file")
    }

    /// A modified close's file is read. An unmodified close's isn't, nor is a file the process couldn't read.
    func testCapturedClose() throws {
        let path = try dylib()
        let modified = try captured(try rawEvent(ES_EVENT_TYPE_NOTIFY_CLOSE, path))
        XCTAssertEqual(modified.event.close?.file_type, "com.apple.mach-o-dylib")
        XCTAssertEqual(modified.event.close?.mach_o_type, "MH_DYLIB")
        let unmodified = try captured(try rawEvent(ES_EVENT_TYPE_NOTIFY_CLOSE, path, modified: false))
        XCTAssertNil(unmodified.event.close?.file_type)
        XCTAssertNil(unmodified.event.close?.mach_o_type)

        chmod(path, 0o600)
        let other = try rawEvent(ES_EVENT_TYPE_NOTIFY_CLOSE, path)
        other.message.pointee.process.pointee.audit_token = RawMessageFixture.auditToken(pid: 123, euid: getuid() + 1)
        XCTAssertNil(try captured(other).event.close?.file_type, "Another user can't read the file")
    }

    /// An event built without a lane, as a trace's is, has no file type: only a capture lane reads the file.
    func testOnlyCaptureReads() throws {
        let fixture = try rawEvent(ES_EVENT_TYPE_NOTIFY_MMAP, try dylib())
        XCTAssertNil(Message(from: fixture.raw).event.mmap?.file_type)
    }

    // MARK: Store and export

    /// The event store keeps both values, and the export writes them.
    func testStoreAndExport() throws {
        let mapped = try captured(try rawEvent(ES_EVENT_TYPE_NOTIFY_MMAP, try dylib()))
        let closed = try captured(try rawEvent(ES_EVENT_TYPE_NOTIFY_CLOSE, try dylib()))
        try withEventStore([mapped, closed]) { context, stored in
            context.refreshAllObjects()
            XCTAssertEqual(stored[0].event.mmap?.file_type, "com.apple.mach-o-dylib")
            XCTAssertEqual(stored[0].event.mmap?.mach_o_type, "MH_DYLIB")
            XCTAssertEqual(stored[1].event.close?.file_type, "com.apple.mach-o-dylib")
            XCTAssertEqual(stored[1].event.close?.mach_o_type, "MH_DYLIB")
        }
        let mmap = try event("mmap", in: try export(mapped))
        XCTAssertEqual(mmap["file_type"] as? String, "com.apple.mach-o-dylib")
        XCTAssertEqual(mmap["mach_o_type"] as? String, "MH_DYLIB")
        XCTAssertEqual(try event("close", in: try export(closed))["mach_o_type"] as? String, "MH_DYLIB")
    }

    /// An event whose file wasn't read writes both keys as `null`.
    func testUnreadExportsNull() throws {
        let path = try dylib()
        for message in [try captured(try rawEvent(ES_EVENT_TYPE_NOTIFY_CLOSE, path, modified: false)),
                        Message(from: try rawEvent(ES_EVENT_TYPE_NOTIFY_MMAP, path).raw)] {
            let name = message.event.mmap == nil ? "close" : "mmap"
            let event = try event(name, in: try export(message))
            XCTAssertTrue(event["file_type"] is NSNull, "\(event)")
            XCTAssertTrue(event["mach_o_type"] is NSNull, "\(event)")
        }
    }

    // MARK: Wire and traces

    /// The wire carries both values, and a 3.0.0 Security Extension's message, which has neither key, decodes with
    /// none.
    func testWire() throws {
        let message = try captured(try rawEvent(ES_EVENT_TYPE_NOTIFY_MMAP, try dylib()))
        XCTAssertEqual(try JSONDecoder().decode(Message.self, from: try wire(message)).event.mmap?.mach_o_type,
                       "MH_DYLIB")
        var object = try jsonObject(try wire(message))
        object[path: "event", "mmap", "_0", "file_type"] = nil
        object[path: "event", "mmap", "_0", "mach_o_type"] = nil
        let legacy = try JSONDecoder().decode(Message.self, from: try JSONSerialization.data(withJSONObject: object))
        XCTAssertEqual(legacy.event.mmap?.source.path, message.event.mmap?.source.path)
        XCTAssertNil(legacy.event.mmap?.file_type)
        XCTAssertNil(legacy.event.mmap?.mach_o_type)
    }

    /// An export opened as a trace keeps both values. One without them gets none, though its file is still on disk:
    /// opening a trace never reads it.
    func testTracesNeverReadTheDisk() throws {
        for type in [ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_NOTIFY_CLOSE] {
            let name = type == ES_EVENT_TYPE_NOTIFY_MMAP ? "mmap" : "close"
            let first = try export(try captured(try rawEvent(type, try dylib())))
            let reopened = try importRecord(first)
            XCTAssertEqual(try event(name, in: try export(reopened)) as NSDictionary,
                           try event(name, in: first) as NSDictionary)
            var stripped = first
            stripped[path: "event", .key(name), "file_type"] = nil
            stripped[path: "event", .key(name), "mach_o_type"] = nil
            let legacy = try event(name, in: try export(try importRecord(stripped)))
            XCTAssertTrue(legacy["file_type"] is NSNull, "\(legacy)")
            XCTAssertTrue(legacy["mach_o_type"] is NSNull, "\(legacy)")
        }
    }

    // MARK: Schema and predicates

    /// Exports with both values, with only a type, and with neither, follow the telemetry schema.
    func testExportsFollowSchema() throws {
        let script = try temporaryFile(bytes: FileTypeSamples.text("#!/bin/zsh\n"))
        let exports = [
            ("mmap of a dylib", try captured(try rawEvent(ES_EVENT_TYPE_NOTIFY_MMAP, try dylib()))),
            ("mmap of a script", try captured(try rawEvent(ES_EVENT_TYPE_NOTIFY_MMAP, script))),
            ("modified close", try captured(try rawEvent(ES_EVENT_TYPE_NOTIFY_CLOSE, script))),
            ("unmodified close", try captured(try rawEvent(ES_EVENT_TYPE_NOTIFY_CLOSE, script, modified: false))),
        ]
        assertValid(exports.map { ($0.0, exportText($0.1)) }, with: try generatedValidator())
    }

    /// Predicates can use both values, on a record and on the stored event alike.
    func testPredicatesUseThem() throws {
        let message = try captured(try rawEvent(ES_EVENT_TYPE_NOTIFY_CLOSE, try dylib()))
        let record = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(exportText(message).utf8))
                                   as? NSDictionary)
        for source in ["event.close.file_type == 'com.apple.mach-o-dylib'", "event.close.mach_o_type == 'MH_DYLIB'"] {
            let predicate = try StreamFilter.Predicate(source)
            XCTAssertTrue(try predicate.evaluate(on: record), source)
            XCTAssertTrue(StoredEventValues.canEvaluate(predicate.parsed), source)
            try withEventStore([message]) { _, stored in
                XCTAssertTrue(StoredEventValues(stored[0]).matches(predicate.parsed), source)
            }
        }
    }
}
