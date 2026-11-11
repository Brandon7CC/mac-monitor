//
//  TelemetryExporterPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Exporting a recording
/// Times File > Export: ``TelemetryExporter`` choosing every event of a SQLite store, fetching them in batches across
/// its workers and writing each as an eslogger-format JSONL record.
final class TelemetryExporterPerformanceTests: PerformanceTestCase {
    /// Events in the store.
    private static let events = 10_000
    
    /// "Export all" of a recording, as JSONL.
    func testExportAll() throws {
        let store = try makeExportStore(try recordingEvents(Self.events))
        let folder = try makeTemporaryDirectory()
        try benchmark("export.jsonl", operations: Self.events, setUp: {
            TelemetryExporter(container: store, pretty: false)
        }) { exporter in
            let written = try run(exporter, to: folder.appendingPathComponent("trace.jsonl"), timeout: 300)
            guard written == Self.events else { throw BenchmarkFailure("Wrote \(written) of \(Self.events)") }
        }
    }
}
