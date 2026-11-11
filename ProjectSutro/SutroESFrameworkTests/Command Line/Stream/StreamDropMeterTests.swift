//
//  StreamDropMeterTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Drop meter
/// Pins how `macmonitor` counts what a stream lost. Gaps are counted per client, so interleaved clients are never
/// drops. Lost types are named, regressions are counted apart from drops, and each report holds only what's new.
final class StreamDropMeterTests: XCTestCase {
    /// A header with sequence numbers.
    ///
    /// - Parameters:
    ///   - type: The event type.
    ///   - seq: Its `seq_num`.
    ///   - global: Its `global_seq_num`.
    /// - Returns: The header.
    private func header(_ type: es_event_type_t, seq: Int? = nil, global: Int?) -> EventHeader {
        EventHeader(sequence: seq, globalSequence: global, eventType: Int(type.rawValue),
                    name: eventTypeToString(from: type), time: "2026-10-05T01:02:03.004005006Z",
                    process: EventHeader.Process(pid: 7, groupID: 7, user: nil, path: nil), context: nil,
                    targetPath: nil)
    }
    
    /// Each client counts from its own `global_seq_num`: interleaving three clients makes no gaps, and only the client
    /// that skipped numbers lost events.
    func testInterleavedClientsAreNotDrops() {
        let meter = StreamDropMeter()
        for global in 1...5 {
            meter.observe(header(ES_EVENT_TYPE_NOTIFY_EXEC, global: global))
            meter.observe(header(ES_EVENT_TYPE_NOTIFY_OPEN, global: global * 10))
            meter.observe(header(ES_EVENT_TYPE_NOTIFY_MMAP, global: global + 100))
        }
        XCTAssertEqual(meter.dropped, 36, "Only the file client's tens are gaps: 4 gaps of 9.")
        XCTAssertEqual(meter.takeReport().map(\.eventClass), [.file])
    }
    
    /// A gap is reported by client and, from `seq_num`, by type. Each report holds only the drops since the last.
    func testReportsAreByClientAndTypeAndOnlyNew() {
        let meter = StreamDropMeter()
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_EXEC, seq: 1, global: 1))
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_EXEC, seq: 4, global: 4))
        let report = meter.takeReport()
        XCTAssertEqual(report, [CaptureDropReport(eventClass: .process, dropped: 2,
                                                  droppedByType: ["ES_EVENT_TYPE_NOTIFY_EXEC": 2])])
        XCTAssertEqual(meter.takeReport(), [])
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_FORK, seq: 1, global: 6))
        XCTAssertEqual(meter.takeReport(), [CaptureDropReport(eventClass: .process, dropped: 1, droppedByType: [:])])
        XCTAssertEqual(meter.dropped, 3)
    }
    
    /// A `global_seq_num` that repeats or goes backwards is a regression, not a drop. Events from before message
    /// version 4, without one, count toward nothing.
    func testRegressionsAndMissingNumbers() {
        let meter = StreamDropMeter()
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_EXEC, global: 5))
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_EXEC, global: 5))
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_EXEC, global: 3))
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_EXEC, global: nil))
        XCTAssertEqual(meter.dropped, 0)
        XCTAssertEqual(meter.regressions, 2)
    }
    
    /// A nonsense event type can't make the meter allocate or trap: it counts toward its client's global sequence only.
    func testNonsenseTypesAreSafe() {
        let meter = StreamDropMeter()
        for type in [-1, 1_000_000_000, Int.max] {
            meter.observe(EventHeader(sequence: 5, globalSequence: 1, eventType: type, name: "?", time: "",
                                      process: EventHeader.Process(pid: 1, groupID: 1, user: nil, path: nil),
                                      context: nil, targetPath: nil))
        }
        XCTAssertEqual(meter.regressions, 2, "All three land on the process client with global 1.")
    }
    
    /// What a stream that left out closes 2, 3 and 5 sees: gaps in close's `seq_num` and the file client's
    /// `global_seq_num`, around contiguous opens.
    ///
    /// - Parameter meter: The meter.
    private func observeLeftOutCloses(_ meter: StreamDropMeter) {
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_CLOSE, seq: 1, global: 1))
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_OPEN, seq: 1, global: 2))
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_CLOSE, seq: 4, global: 5))
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_OPEN, seq: 2, global: 6))
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_CLOSE, seq: 6, global: 8))
    }
    
    /// The gaps a field filter leaves in its type's `seq_num` and its client's `global_seq_num` are no loss.
    func testFieldFilteredGapsAreNotLosses() {
        let meter = StreamDropMeter()
        meter.fieldFilteredTypes = [Int(ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue)]
        observeLeftOutCloses(meter)
        XCTAssertEqual(meter.dropped, 0)
        XCTAssertEqual(meter.takeReport(), [])
    }
    
    /// Another type of the filtered class still reports its losses, from its own `seq_num`.
    func testOtherTypesOfAFilteredClassStillReportLosses() {
        let meter = StreamDropMeter()
        meter.fieldFilteredTypes = [Int(ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue)]
        observeLeftOutCloses(meter)
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_OPEN, seq: 4, global: 10))
        XCTAssertEqual(meter.dropped, 1)
        XCTAssertEqual(meter.takeReport(), [CaptureDropReport(eventClass: .file, dropped: 1,
                                                              droppedByType: ["ES_EVENT_TYPE_NOTIFY_OPEN": 1])])
    }
    
    /// Classes without a filtered type keep counting every `global_seq_num` gap, typed or not.
    func testOtherClassesKeepGlobalAccounting() {
        let meter = StreamDropMeter()
        meter.fieldFilteredTypes = [Int(ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue)]
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_EXEC, global: 1))
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_EXEC, global: 3))
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_MMAP, seq: 1, global: 1))
        meter.observe(header(ES_EVENT_TYPE_NOTIFY_MMAP, seq: 2, global: 4))
        XCTAssertEqual(meter.dropped, 3)
        XCTAssertEqual(meter.takeReport().map(\.eventClass), [.process, .memory])
    }
    
    /// With no filtered types, as from a Security Extension older than 3.1.0, every gap is a loss again.
    func testClearingTheFilteredTypesCountsEveryGap() {
        let meter = StreamDropMeter()
        meter.fieldFilteredTypes = [Int(ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue)]
        observeLeftOutCloses(meter)
        meter.fieldFilteredTypes = []
        XCTAssertEqual(meter.dropped, 3)
        XCTAssertEqual(meter.takeReport().map(\.dropped), [3])
    }
}
