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
/// reads into the wrong place, or fills with a default.
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
    /// - `get_task_allow`: the store doesn't keep it, so it isn't exported.
    /// - `argc`: not exported. eslogger has only `args`.
    /// - `authorizationFlags`: a petition's table of flag names, not a field of the event.
    private static let derived: Set<String> = ["id", "message_darwin_time", "get_task_allow", "argc",
                                               "authorizationFlags"]
    
    /// Each synthetic event exported, then imported, is the event it was.
    func testEveryEventSurvivesExportAndImport() throws {
        var report: [String] = []
        for record in try SyntheticCorpus.records() {
            let imported = try importRecord(exportText(record.message))
            report += differences(try wire(record.message), try wire(imported), ignoring: Self.derived)
                .map { "\(record.label) \($0)" }
        }
        XCTAssertEqual(report, [], report.joined(separator: "\n"))
    }
}
