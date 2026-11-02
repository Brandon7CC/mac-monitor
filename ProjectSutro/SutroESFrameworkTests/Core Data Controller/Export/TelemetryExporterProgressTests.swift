//
//  TelemetryExporterProgressTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/25/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - Export progress
/// Pins what an export tells the toolbar while it saves: how many of its events it has written, from none to every one,
/// and that Cancel, whenever it comes before the rename, leaves the file it would have replaced as it was.
final class TelemetryExporterProgressTests: XCTestCase {
    /// Two full batches and a short third.
    private let count = TelemetryExporter.batchSize * 2 + 234

    /// A store on disk holding ``count`` events, all saved in batch 1.
    ///
    /// - Returns: The store.
    /// - Throws: The error loading the store, reading the fixture, or saving the events.
    private func makeStore() throws -> NSPersistentContainer {
        let exit = try importRecord(try fixtureObject("eslogger-exit.jsonl"))
        return try makeExportStore((0..<count).map { order in
            var message = exit
            message.id = UUID()
            message.mach_time = Int64(order)
            return message
        })
    }

    /// Export every event over `url`, one batch a round, reporting after every round.
    ///
    /// - Parameters:
    ///   - url: The destination.
    ///   - cancelAt: Cancels the export from the first report it's true for.
    /// - Returns: How the export ended and every report it made.
    /// - Throws: The error building the store.
    private func export(to url: URL, cancelAt: @escaping (TelemetryExporter.Progress) -> Bool = { _ in false }) throws
        -> (result: Result<Int, Error>, reports: [TelemetryExporter.Progress]) {
        let exporter = TelemetryExporter(container: try makeStore(), pretty: false, reportInterval: 0, workers: 1)
        var reports: [TelemetryExporter.Progress] = []
        let result = Result {
            try run(exporter, to: url, timeout: 60) {
                reports.append($0)
                if cancelAt($0) { exporter.cancel() }
            }
        }
        return (result, reports)
    }

    /// One report once the events are chosen, with none written, one after each batch, and one once the file is in
    /// place. The total never changes.
    func testReportsEveryBatchWritten() throws {
        let url = try makeTemporaryDirectory().appendingPathComponent("trace.jsonl")
        let (result, reports) = try export(to: url)

        XCTAssertEqual(try result.get(), count)
        XCTAssertEqual(reports.map(\.written), [0, 500, 1_000, count, count])
        XCTAssertEqual(Set(reports.map(\.total)), [count])
        XCTAssertEqual(reports.last?.fraction, 1)
    }

    /// Cancel stops the save with `CancellationError`, leaves the file it would have replaced as it was, and takes its
    /// temporary file away: before the first batch, and during the last, which the batch loop no longer checks for.
    func testCancelLeavesTheFileAsItWas() throws {
        let cases: [(moment: String, cancelAt: (TelemetryExporter.Progress) -> Bool, reported: [Int])] = [
            ("before the first batch", { _ in true }, [0]),
            ("during the last batch", { $0.written == self.count }, [0, 500, 1_000, count]),
        ]
        for (moment, cancelAt, reported) in cases {
            let folder = try makeTemporaryDirectory()
            let url = folder.appendingPathComponent("trace.jsonl")
            let earlier = Data("an earlier trace\n".utf8)
            try earlier.write(to: url)

            let (result, reports) = try export(to: url, cancelAt: cancelAt)

            XCTAssertThrowsError(try result.get(), moment) {
                XCTAssertTrue($0 is CancellationError, "\(moment): \($0)")
            }
            XCTAssertEqual(try Data(contentsOf: url), earlier, moment)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: folder.path), ["trace.jsonl"], moment)
            /// Nothing after the Cancel: no report of the file in place.
            XCTAssertEqual(reports.map(\.written), reported, moment)
        }
    }
}
