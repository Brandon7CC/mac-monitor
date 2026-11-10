//
//  IndicatorExchangeTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Sharing indicators
/// Pins the file Settings > Indicators exports and imports: what it writes, what it reads, what it refuses, and how
/// an import merges.
final class IndicatorExchangeTests: XCTestCase {
    /// Every indicator Mac Monitor ships comes back from its file as it went in, edits and all.
    func testRoundTrip() throws {
        var edited = Indicator.defaults
        edited[0].tableMarks = []
        edited[1].isEnabled = false
        edited[2].tactic = nil
        edited[3].severity = edited[3].severity == .high ? .low : .high
        let data = try IndicatorExchange.data(of: edited)
        XCTAssertEqual(try IndicatorExchange.indicators(from: data), edited)
        let file = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let listed = try XCTUnwrap(file["indicators"] as? [[String: Any]])
        XCTAssertEqual(listed.map { $0["severity"] as? String }, edited.map(\.severity.rawValue))
        XCTAssertEqual(file["format"] as? String, "com.swiftlydetecting.indicators")
        XCTAssertEqual(file["version"] as? Int, 1)
        XCTAssertEqual((file["indicators"] as? [Any])?.count, edited.count)
    }

    /// A bare array of indicators imports, and so does one indicator alone.
    func testBareIndicatorsImport() throws {
        let one = Indicator.defaults[3]
        let array = try JSONEncoder().encode([one, Indicator.defaults[4]])
        XCTAssertEqual(try IndicatorExchange.indicators(from: array), [one, Indicator.defaults[4]])
        XCTAssertEqual(try IndicatorExchange.indicators(from: try JSONEncoder().encode(one)), [one])
    }

    /// An indicator written by hand needs only a name and a predicate: it's new, on, and shown in Correlation and
    /// Groups, with a dot in the tables.
    func testHandWrittenIndicatorImports() throws {
        let file = Data(#"""
        {"format": "com.swiftlydetecting.indicators", "version": 1, "indicators": [
          {"name": "curl to a raw IP", "predicate": "event.exec.command_line MATCHES \".*curl .*[0-9]+\\\\.[0-9]+.*\"",
           "tactic": "commandAndControl", "technique": "T1105"}
        ]}
        """#.utf8)
        let indicator = try XCTUnwrap(try IndicatorExchange.indicators(from: file).first)
        XCTAssertEqual(indicator.name, "curl to a raw IP")
        XCTAssertEqual(indicator.tactic, .commandAndControl)
        XCTAssertEqual(indicator.technique, "T1105")
        XCTAssertTrue(indicator.isEnabled)
        XCTAssertEqual(indicator.tableMarks, .dot)
        XCTAssertEqual(indicator.description, "")
        XCTAssertEqual(indicator.severity, .medium, "Missing means medium")
        XCTAssertNil(indicator.problem)
        XCTAssertNotEqual(try IndicatorExchange.indicators(from: file).first?.id, indicator.id, "Each import is new")
    }

    /// A hand-written indicator's severity is read when it names one, and is medium when it names one this build
    /// doesn't know. Each severity comes back from a file as it went in.
    func testHandWrittenSeverityImports() throws {
        func imported(_ severity: String) throws -> IndicatorSeverity? {
            let file = #"[{"name": "Mine", "predicate": "TRUEPREDICATE", "severity": \#(severity)}]"#
            return try IndicatorExchange.indicators(from: Data(file.utf8)).first?.severity
        }
        XCTAssertEqual(try imported(#""high""#), .high)
        XCTAssertEqual(try imported(#""low""#), .low)
        XCTAssertEqual(try imported(#""critical""#), .medium)
        XCTAssertEqual(try imported("null"), .medium)
        for severity in IndicatorSeverity.allCases {
            var indicator = Indicator.defaults[0]
            indicator.severity = severity
            XCTAssertEqual(try IndicatorExchange.indicators(from: IndicatorExchange.data(of: [indicator])), [indicator])
        }
    }

    /// What isn't a file of indicators says why.
    func testRefusesWhatIsNotIndicators() {
        func message(_ text: String) -> String? {
            do {
                _ = try IndicatorExchange.indicators(from: Data(text.utf8))
                return nil
            } catch {
                return (error as? IndicatorExchange.ImportError)?.message
            }
        }
        XCTAssertEqual(message("not json"), "The file isn't JSON.")
        XCTAssertEqual(message(#"{"format": "other", "version": 1, "indicators": []}"#),
                       "The file isn't Mac Monitor indicators.")
        XCTAssertEqual(message(#"{"format": "com.swiftlydetecting.indicators", "version": 2, "indicators": []}"#),
                       "The file is from a newer Mac Monitor. Update to import it.")
        XCTAssertEqual(message(#"{"format": "com.swiftlydetecting.indicators", "version": 1, "indicators": []}"#),
                       "The file has no indicators.")
        XCTAssertEqual(message(#"[{"name": "No predicate"}]"#), "An indicator in the file has no predicate.")
        XCTAssertEqual(message(#"[{"name": "Bad", "predicate": "x", "isEnabled": "yes"}]"#),
                       "An indicator in the file has a value for isEnabled that can't be read.")
    }

    /// An import replaces an indicator with its identity in place, and adds the rest at the end, in order.
    func testMergeReplacesInPlaceAndAppends() {
        var changed = Indicator.defaults[1]
        changed.name = "Renamed"
        let new = Indicator(name: "New", description: "", symbol: "star", color: .red, predicate: "event_type >= 0")
        let merged = IndicatorExchange.merge([new, changed], into: Array(Indicator.defaults.prefix(3)))
        XCTAssertEqual(merged.indicators.map(\.name),
                       [Indicator.defaults[0].name, "Renamed", Indicator.defaults[2].name, "New"])
        XCTAssertEqual(merged.added, 1)
        XCTAssertEqual(merged.replaced, 1)
    }

    /// Import reads a regular file of at most 4 MiB, checked before it's read: a larger file, or a folder, is
    /// refused with why.
    func testImportReadsOnlyAFileWithinTheCap() throws {
        let directory = try makeTemporaryDirectory(prefix: "IndicatorExchangeTests")
        let file = directory.appendingPathComponent("indicators.json")
        try IndicatorExchange.data(of: [Indicator.defaults[0]]).write(to: file)
        XCTAssertEqual(try IndicatorExchange.indicators(contentsOf: file), [Indicator.defaults[0]])
        XCTAssertEqual(IndicatorExchange.maxFileBytes, 4 << 20)

        let large = directory.appendingPathComponent("large.json")
        try Data(repeating: 0x20, count: IndicatorExchange.maxFileBytes + 1).write(to: large)
        let tooLarge = thrown(IndicatorExchange.ImportError.self) {
            try IndicatorExchange.indicators(contentsOf: large)
        }
        XCTAssertEqual(tooLarge?.message, "The file is over 4 MiB, the most Import reads.")
        let folder = thrown(IndicatorExchange.ImportError.self) {
            try IndicatorExchange.indicators(contentsOf: directory)
        }
        XCTAssertEqual(folder?.message, "Only a file can be imported.")
    }
}
