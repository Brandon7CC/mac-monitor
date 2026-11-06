//
//  StreamFilterPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Filtering a stream
/// Times `macmonitor stream`'s filters (``StreamFilter``): on an event's header (`--pid`, `--process`), on its record
/// (`--predicate`, `--grep`), and the whole pipeline a `--predicate` runs, which decodes each wire event and encodes
/// its record before the predicate reads it.
final class StreamFilterPerformanceTests: PerformanceTestCase {
    /// Events per sample.
    private static let events = 2_000
    /// A predicate a person types: root's events from `/usr`.
    private static let predicate = "process.executable.path BEGINSWITH '/usr/' AND process.audit_token.euid == 0"
    
    /// The recording's records, parsed, as the pipeline hands them to the filter.
    ///
    /// - Returns: The records.
    /// - Throws: The error making the events, or an `XCTest` failure if a record isn't a JSON object.
    private func records() throws -> [NSDictionary] {
        try recordingEvents(Self.events).map { try jsonObject(Data(exportText($0).utf8)) as NSDictionary }
    }
    
    /// Run a filter on each record.
    ///
    /// - Parameters:
    ///   - name: The benchmark's name.
    ///   - filter: The filter.
    /// - Throws: The filter's error, or the error writing the results.
    private func benchmarkRecords(_ name: String, _ filter: StreamFilter) throws {
        let records = try records()
        try benchmark(name, unit: "record", operations: records.count) {
            for record in records { _ = try filter.admits(record: record) }
        }
    }
    
    /// `--process` and `--pid`: decoding each wire event's header, then matching it.
    func testHeader() throws {
        let wires = try recordingEvents(Self.events).map(wire)
        var filter = StreamFilter()
        filter.processes = [try StreamFilter.Pattern("/(zsh|curl)$", option: "--process")]
        filter.pids = [100, 200, 300]
        let decoder = JSONDecoder()
        try benchmark("filter.header", operations: wires.count) {
            for wire in wires { _ = filter.admits(try decoder.decode(EventHeader.self, from: wire)) }
        }
    }
    
    /// `--predicate`, on records already parsed.
    func testPredicate() throws {
        var filter = StreamFilter()
        filter.predicates = [try StreamFilter.Predicate(Self.predicate)]
        try benchmarkRecords("filter.predicate", filter)
    }
    
    /// `--grep`, which tries every string of a record.
    func testGrep() throws {
        var filter = StreamFilter()
        filter.greps = [try StreamFilter.Pattern("(?i)authorization", option: "--grep")]
        try benchmarkRecords("filter.grep", filter)
    }
    
    /// `macmonitor stream --predicate` from wire events to the JSONL it writes, on one encoder.
    func testStreamPipelineWithPredicate() throws {
        let wires = try recordingEvents(Self.events).map(wire)
        var filter = StreamFilter()
        filter.predicates = [try StreamFilter.Predicate(Self.predicate)]
        let nobody = PipelineScope(ancestry: [PipelineAncestor(pid: .max, groupID: 0, path: "/x/macmonitor")],
                                   includeSelf: false)
        try benchmark("filter.stream.predicate", operations: wires.count, setUp: {
            StreamPipeline(formatter: .jsonl([ExportEncoder(model: eventModel)]), scope: nobody, forTerminal: false,
                           filter: filter)
        }) { pipeline in
            _ = pipeline.process(wires)
            guard pipeline.unchecked == 0, pipeline.unreadable == 0 else {
                throw BenchmarkFailure("\(pipeline.unchecked) unchecked, \(pipeline.unreadable) unreadable")
            }
        }
    }
}
