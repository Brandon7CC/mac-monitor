//
//  TelemetryVersionTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - The telemetry version on every record
/// Pins `telemetry_version`: every exported record carries Mac Monitor's telemetry version beside eslogger's
/// `schema_version`, an import ignores it, and the Security Extension's wire format, which isn't telemetry, doesn't
/// carry it.
final class TelemetryVersionTests: XCTestCase {
    /// The synthetic eslogger exit event, read as File > Open Trace… reads it.
    ///
    /// - Returns: The event.
    /// - Throws: The error reading the fixture.
    private func exitEvent() throws -> Message {
        try importRecord(try fixtureObject("eslogger-exit.jsonl"))
    }
    
    /// The export the command line streams (an event encoded without a store) carries the version, and eslogger's
    /// `schema_version` and `version` are eslogger's.
    ///
    /// - Throws: The error reading the fixture or parsing the export.
    func testStorelessExportCarriesTheVersion() throws {
        let fixture = try fixtureObject("eslogger-exit.jsonl")
        let record = try export(try exitEvent())
        XCTAssertEqual(record[TelemetrySchema.versionKey] as? String, TelemetrySchema.version)
        XCTAssertEqual(record["schema_version"] as? Int, 1)
        XCTAssertEqual(record["version"] as? Int, fixture["version"] as? Int)
    }
    
    /// "Export all" writes the version on every record, as JSONL and as pretty JSON.
    ///
    /// - Throws: The error building the store, exporting it, or reading the export.
    func testExportedFilesCarryTheVersion() throws {
        let exit = try exitEvent()
        let store = try makeExportStore((0..<3).map { _ in
            var message = exit
            message.id = UUID()
            return message
        })
        for pretty in [false, true] {
            let (url, events) = try exportAll(store, pretty: pretty)
            XCTAssertEqual(events, 3)
            let reader = try TraceRecordReader(url: url)
            var versions: [String?] = []
            while case .object(let json, _)? = try reader.next() {
                let record = try XCTUnwrap(try JSONSerialization.jsonObject(with: json) as? [String: Any])
                versions.append(record[TelemetrySchema.versionKey] as? String)
            }
            XCTAssertEqual(versions, Array(repeating: TelemetrySchema.version, count: 3), pretty ? "pretty" : "JSONL")
        }
    }
    
    /// A record's telemetry version is ignored on import: a record of another version reads as the same event, and its
    /// re-export carries the version it's written in.
    ///
    /// - Throws: The error reading the fixture or importing the records.
    func testImportIgnoresTheVersion() throws {
        var record = try export(try exitEvent())
        record[TelemetrySchema.versionKey] = "0.0.1"
        let versioned = try importRecord(record)
        record.removeValue(forKey: TelemetrySchema.versionKey)
        let unversioned = try importRecord(record)
        /// Every value the event exports is the same; only the values' own `id`s, which aren't exported, differ.
        XCTAssertEqual(exportText(versioned), exportText(unversioned))
        XCTAssertEqual(try export(versioned)[TelemetrySchema.versionKey] as? String, TelemetrySchema.version)
    }
    
    /// The Security Extension's wire format isn't telemetry: it doesn't carry the version.
    ///
    /// - Throws: The error parsing the JSON, or an `XCTest` failure if there's none.
    func testWireFormatHasNoVersion() throws {
        let exit = sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, seq: 1, global: 1)
        let lane = LaneContext(eventClass: .process, sensorID: "SENSOR-1", encoder: StreamingJSONEncoder())
        let json = try XCTUnwrap(MessageSerializer().serialize(exit.raw, in: lane))
        let wire = try XCTUnwrap(try JSONSerialization.jsonObject(with: json) as? [String: Any])
        XCTAssertNotNil(wire["schema_version"])
        XCTAssertNil(wire[TelemetrySchema.versionKey])
    }
    
    /// eslogger's records, which name no telemetry version, export with Mac Monitor's: the version is the exporter's,
    /// whatever event type the record is and whatever it names.
    ///
    /// - Throws: The error reading a fixture, importing a record, or parsing an export.
    func testESLoggerRecordsExportWithTheVersion() throws {
        for name in ["eslogger-exit.jsonl", "eslogger-open.jsonl", "eslogger-lineage.jsonl"] {
            for record in try fixtureRecords(name) {
                let exported = try export(try importRecord(record))
                XCTAssertEqual(exported[TelemetrySchema.versionKey] as? String, TelemetrySchema.version, name)
                XCTAssertEqual(exported["schema_version"] as? Int, record["schema_version"] as? Int, name)
            }
        }
    }
}
