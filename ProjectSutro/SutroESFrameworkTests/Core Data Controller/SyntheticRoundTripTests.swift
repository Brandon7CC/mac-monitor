//
//  SyntheticRoundTripTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/22/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Round trips
/// Every event type, exported and read back, keeps every value it had: no field the export leaves out or the import
/// reads into the wrong place, or fills with a default. The two are compared both ways, so a value the import makes up
/// where the event had none (a `nil` the encoder leaves out) is a difference too.
final class SyntheticRoundTripTests: XCTestCase {
    /// A message as plain JSON values, in its own wire form.
    ///
    /// - Parameter message: The message.
    /// - Returns: Its `JSONSerialization` object.
    /// - Throws: The error encoding it.
    private func wire(_ message: Message) throws -> Any {
        try JSONSerialization.jsonObject(with: try JSONEncoder().encode(message))
    }
    
    /// Fields the round trip doesn't compare, because they're derived rather than recorded:
    /// - `id`: each import makes new ones.
    /// - `message_darwin_time`: read back from `time`, to the nanosecond the synthetic `Date` doesn't have.
    /// - `argc`: not exported. eslogger has only `args`.
    private static let derived: Set<String> = ["id", "message_darwin_time", "argc"]
    
    /// What an event that lacks a value is read back with, by key: the only keys the import may have that the event
    /// doesn't, and only with these values.
    /// - `seq_num`, `global_seq_num`: stored as 0, and exported because the message's version says it has them.
    /// - `context`, `target_path`: the store's placeholder for an event that has neither.
    /// - `sha256`: eslogger's spelling of a Gatekeeper override's missing hash.
    /// - `process_age_ms`, `executable_age_ms`: worked out on import from the process's start and the event's time,
    ///   which the empty records share.
    private static let readBackForMissing: [String: Any] = [
        "seq_num": 0, "global_seq_num": 0, "context": "Not supported", "target_path": "Not supported",
        "sha256": "NULL", "process_age_ms": 0, "executable_age_ms": 0,
    ]
    
    /// Each synthetic event exported, then imported, is the event it was.
    func testEveryEventSurvivesExportAndImport() throws {
        var report: [String] = []
        for record in try SyntheticCorpus.records() {
            let imported = try importRecord(exportText(record.message))
            report += differences(try wire(record.message), try wire(imported), ignoring: Self.derived, exact: true,
                                  allowing: Self.readBackForMissing).map { "\(record.label) \($0)" }
        }
        XCTAssertEqual(report, [], report.joined(separator: "\n"))
    }
}
