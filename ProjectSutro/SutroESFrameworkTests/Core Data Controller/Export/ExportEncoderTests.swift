//
//  ExportEncoderTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Export encoder
/// Pins `macmonitor`'s JSONL to Mac Monitor's export: for real events, a record is byte for byte what Export
/// telemetry ▸ JSONL (lines) writes from the event store, also after the trip over the wire, and many events through
/// one encoder never leak into each other.
final class ExportEncoderTests: XCTestCase {
    /// Every fixture's events, encoded one per line, are byte for byte the export of the same events saved in a store
    /// on disk (which joins records with newlines and ends without one).
    func testRecordsMatchTheStoresExport() throws {
        let messages = try allFixtureMessages()
        let encoder = ExportEncoder(model: eventModel)
        var lines = messages.reduce(into: Data()) { $0.append(encoder.line(for: $1)) }
        XCTAssertEqual(lines.removeLast(), 0x0A)
        let trace = CoreDataController.EventSource.trace(URL(fileURLWithPath: "/tmp/trace.jsonl"))
        let exported = try exportAll(try makeExportStore(messages), from: trace, timeout: 10).url
        XCTAssertEqual(String(decoding: lines, as: UTF8.self),
                       String(decoding: try Data(contentsOf: exported), as: UTF8.self))
    }
    
    /// After the trip over the wire (the capture lane's encoder, then `JSONDecoder`), a record is still exactly the
    /// export of the original event, and ends in exactly one newline.
    func testTheWireChangesNothing() throws {
        let encoder = ExportEncoder(model: eventModel)
        for message in try allFixtureMessages() {
            let received = try JSONDecoder().decode(Message.self, from: try wire(message))
            let line = String(decoding: encoder.line(for: received), as: UTF8.self)
            XCTAssertEqual(line, exportText(message) + "\n", message.es_event_type)
            XCTAssertFalse(line.dropLast().contains("\n"))
        }
    }
    
    /// Many events through one encoder, reset after each batch as the pipeline does, stay byte for byte what a fresh
    /// encoder writes: no rows leak from one event or batch into the next.
    func testManyEventsDontLeakIntoEachOther() throws {
        let messages = try allFixtureMessages()
        let expected = messages.map { ExportEncoder(model: eventModel).line(for: $0) }
        let encoder = ExportEncoder(model: eventModel)
        for round in 0..<(2_000 / messages.count) {
            for (index, message) in messages.enumerated() {
                XCTAssertEqual(encoder.line(for: message), expected[index], "round \(round), event \(index)")
            }
            if round % 3 == 2 { encoder.reset() }
        }
    }
}
