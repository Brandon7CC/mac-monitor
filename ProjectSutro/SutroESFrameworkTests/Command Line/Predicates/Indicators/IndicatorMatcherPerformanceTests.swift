//
//  IndicatorMatcherPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/7/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - Indicators per row
/// Times finding an event's indicators: what the event tables do once for each row they show, for its dot, and what
/// Export telemetry does for every record it lists them in.
final class IndicatorMatcherPerformanceTests: PerformanceTestCase {
    /// Events in the store.
    private static let events = 2_000

    /// A row's marks, as the tables find them: the built-in marks other than the indicators' twins, then every shipped
    /// indicator, on stored events. A row's marks are found once, for the rows on screen.
    func testMarksPerRow() throws {
        let store = try makeExportStore(try recordingEvents(Self.events))
        let context = store.newBackgroundContext()
        let messages = try context.performAndWait { try context.fetch(ESMessage.request(where: nil, loaded: true)) }
        guard messages.count == Self.events else { throw BenchmarkFailure("Fetched \(messages.count)") }
        try benchmark("marks.row", unit: "row", operations: messages.count, setUp: {
            let twins = Set(Indicator.defaults.map(\.id))
            return (IndicatorMatcher(Indicator.builtInMarks.filter { !twins.contains($0.id) }),
                    IndicatorMatcher(Indicator.defaults))
        }) { matchers in
            context.performAndWait {
                for message in messages {
                    _ = matchers.0.matches(message)
                    _ = matchers.1.matches(message)
                }
            }
        }
    }

    /// A row's indicators when there are many: 500 indicators, each a shipped one's rule made distinct, so none is
    /// evaluated once for another (``IndicatorMatcher``), as a shared collection of indicators might be. Those that
    /// compare only what the stored event holds, then those that also read a key only the record has.
    func testMarksPerRowWithManyStoredIndicators() throws {
        try benchmarkMany("marks.row.500.stored", extra: "event_type")
    }

    /// The same 500, each also reading a key only the record has, so every event's record is encoded.
    func testMarksPerRowWithManyRecordIndicators() throws {
        try benchmarkMany("marks.row.500.record", extra: "global_seq_num")
    }

    /// - Parameters:
    ///   - name: The benchmark's name.
    ///   - extra: The key each rule also compares, to make it distinct.
    private func benchmarkMany(_ name: String, extra: String) throws {
        let store = try makeExportStore(try recordingEvents(Self.events))
        let context = store.newBackgroundContext()
        let messages = try context.performAndWait { try context.fetch(ESMessage.request(where: nil, loaded: true)) }
        guard messages.count == Self.events else { throw BenchmarkFailure("Fetched \(messages.count)") }
        let many = (0..<500).map { index -> Indicator in
            var indicator = Indicator.defaults[index % Indicator.defaults.count]
            indicator.id = UUID()
            indicator.predicate = "(\(indicator.predicate)) AND \(extra) != -\(index + 1)"
            return indicator
        }
        try benchmark(name, unit: "row", operations: messages.count, setUp: {
            IndicatorMatcher(many)
        }) { matcher in
            context.performAndWait {
                for message in messages { _ = matcher.matches(message) }
            }
        }
    }

    /// "Export all" of a recording as JSONL, with every record listing the shipped indicators it matches. Compare
    /// `export.jsonl`, without them.
    func testExportWithIndicators() throws {
        let store = try makeExportStore(try recordingEvents(10_000))
        let folder = try makeTemporaryDirectory()
        try benchmark("export.jsonl.indicators", operations: 10_000, setUp: {
            TelemetryExporter(container: store, pretty: false, indicators: Indicator.defaults)
        }) { exporter in
            let written = try run(exporter, to: folder.appendingPathComponent("trace.jsonl"), timeout: 300)
            guard written == 10_000 else { throw BenchmarkFailure("Wrote \(written) of 10,000") }
        }
    }
}
