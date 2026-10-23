//
//  CaptureDropAccountingTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Drops per capture client
/// Pins how a capture session counts what Endpoint Security dropped: per client, from every message the client was
/// handed, and reported once.
final class CaptureDropAccountingTests: XCTestCase {
    private var factory = FakeEndpointSecurityClientFactory()
    
    /// A fresh factory for each test.
    override func setUp() {
        super.setUp()
        factory = FakeEndpointSecurityClientFactory()
    }
    
    /// Hand one client messages of one event type, as Endpoint Security would.
    ///
    /// - Parameters:
    ///   - type: The event type.
    ///   - eventClass: Which client gets them.
    ///   - seq: Each message's `seq_num`, which counts that event type.
    ///   - global: Each message's `global_seq_num`, which counts everything the client was sent. Same as `seq` if
    ///     left out.
    private func deliver(_ type: es_event_type_t, to eventClass: EventClass, seq: [UInt64], global: [UInt64]? = nil) {
        let client = factory.client(eventClass)
        for (seq, global) in zip(seq, global ?? seq) {
            client.deliver(sequencedMessage(type, seq: seq, global: global))
        }
    }
    
    /// One lane's statistics.
    ///
    /// - Parameters:
    ///   - session: The session.
    ///   - eventClass: The lane's class.
    /// - Returns: Its statistics.
    /// - Throws: An `XCTest` failure if the session has no such lane.
    private func statistics(_ session: CaptureSession, _ eventClass: EventClass) throws -> CaptureLaneStatistics {
        try XCTUnwrap(session.statistics().first { $0.eventClass == eventClass })
    }
    
    /// A gap in one client's `global_seq_num` is that client's drop alone: each client numbers its own messages.
    func testGlobalGapsArePerClient() throws {
        let session = try makeSession(factory: factory)
        session.isRecording = true
        // The process client never gets messages 12 and 13. Both were execs (exec 3 and 4).
        deliver(ES_EVENT_TYPE_NOTIFY_EXEC, to: .process, seq: [1, 2, 5], global: [10, 11, 14])
        // The file client gets everything. Its numbers start at 10 too.
        deliver(ES_EVENT_TYPE_NOTIFY_OPEN, to: .file, seq: [1, 2, 3], global: [10, 11, 12])
        let process = try statistics(session, .process)
        XCTAssertEqual(process.messages, 3)
        XCTAssertEqual(process.dropped, 2)
        XCTAssertEqual(process.gaps, 1)
        XCTAssertEqual(process.droppedByType, ["ES_EVENT_TYPE_NOTIFY_EXEC": 2])
        let file = try statistics(session, .file)
        XCTAssertEqual(file.messages, 3)
        XCTAssertEqual(file.dropped, 0)
    }
    
    /// Each lane reports how many of the session's event types it subscribed to.
    func testEachLaneReportsItsSubscriptions() throws {
        let session = try makeSession(factory: factory)
        for eventClass in EventClass.allCases {
            XCTAssertEqual(try statistics(session, eventClass).subscribedEvents,
                           session.subscribedEvents.filter { EventClassTable.eventClass(of: $0) == eventClass }.count,
                           eventClass.rawValue)
        }
    }
    
    /// Messages handed over while not recording are counted, so they're never mistaken for drops later.
    func testMessagesWhileNotRecordingAreNotDrops() throws {
        let session = try makeSession(factory: factory)
        deliver(ES_EVENT_TYPE_NOTIFY_EXIT, to: .process, seq: [1, 2])
        session.isRecording = true
        deliver(ES_EVENT_TYPE_NOTIFY_EXIT, to: .process, seq: [3, 4])
        let process = try statistics(session, .process)
        XCTAssertEqual(process.messages, 4)
        XCTAssertEqual(process.dropped, 0)
    }
    
    /// A drop report names the client and the types it lost, and only has drops since the last one.
    func testDropReportHasOnlyNewDrops() throws {
        let session = try makeSession(factory: factory)
        XCTAssertTrue(session.takeDropReport().isEmpty)
        deliver(ES_EVENT_TYPE_NOTIFY_OPEN, to: .file, seq: [1, 4])
        XCTAssertEqual(session.takeDropReport(), [CaptureDropReport(eventClass: .file, dropped: 2,
                                                                    droppedByType: ["ES_EVENT_TYPE_NOTIFY_OPEN": 2])])
        XCTAssertTrue(session.takeDropReport().isEmpty)
        deliver(ES_EVENT_TYPE_NOTIFY_OPEN, to: .file, seq: [5])
        // Message 6 never arrives, but no type's own count skips, so it isn't put on a type.
        deliver(ES_EVENT_TYPE_NOTIFY_CLOSE, to: .file, seq: [1], global: [7])
        deliver(ES_EVENT_TYPE_NOTIFY_MMAP, to: .memory, seq: [1, 3])
        XCTAssertEqual(session.takeDropReport(), [
            CaptureDropReport(eventClass: .file, dropped: 1, droppedByType: [:]),
            CaptureDropReport(eventClass: .memory, dropped: 1, droppedByType: ["ES_EVENT_TYPE_NOTIFY_MMAP": 1])
        ])
        XCTAssertEqual(try statistics(session, .file).dropped, 3)
    }
    
    /// Drops are logged at most once a second, and the report waits for the next chance.
    func testDropReportsAreRateLimited() throws {
        let session = try makeSession(factory: factory)
        let second = CaptureSession.dropReportInterval
        XCTAssertTrue(session.reportDrops(now: second).isEmpty)
        deliver(ES_EVENT_TYPE_NOTIFY_EXEC, to: .process, seq: [1, 3])
        XCTAssertTrue(session.reportDrops(now: second + second / 2).isEmpty)
        XCTAssertEqual(session.reportDrops(now: 2 * second).map(\.dropped), [1])
        XCTAssertTrue(session.reportDrops(now: 4 * second).isEmpty)
    }
    
    /// A `global_seq_num` that repeats or goes backwards, which Endpoint Security should never send, is counted apart
    /// from drops.
    func testSequenceRegressionsAreCounted() throws {
        let session = try makeSession(factory: factory)
        // 5 repeats, then goes back to 4.
        deliver(ES_EVENT_TYPE_NOTIFY_EXIT, to: .process, seq: [1, 2, 3, 4], global: [5, 5, 4, 5])
        let process = try statistics(session, .process)
        XCTAssertEqual(process.regressions, 2)
        XCTAssertEqual(process.dropped, 0)
        XCTAssertEqual(process.gaps, 0)
        XCTAssertEqual(try statistics(session, .file).regressions, 0)
    }
    
    /// Events that can't be serialized are counted, apart from drops.
    func testSerializationFailuresAreCounted() throws {
        let session = try makeSession(factory: factory, serializer: StubSerializer { _, _ in nil })
        session.isRecording = true
        deliver(ES_EVENT_TYPE_NOTIFY_EXIT, to: .process, seq: [1, 2])
        let process = try statistics(session, .process)
        XCTAssertEqual(process.serializationFailures, 2)
        XCTAssertEqual(process.dropped, 0)
    }
    
    /// A drop report lists the types lost, most first.
    func testTypeSummaryListsTheMostDroppedFirst() {
        let report = CaptureDropReport(eventClass: .file, dropped: 125, droppedByType: [
            "ES_EVENT_TYPE_NOTIFY_CLOSE": 20, "ES_EVENT_TYPE_NOTIFY_OPEN": 100, "ES_EVENT_TYPE_NOTIFY_DUP": 5,
            "ES_EVENT_TYPE_NOTIFY_CREATE": 5
        ])
        XCTAssertEqual(report.typeSummary, "ES_EVENT_TYPE_NOTIFY_OPEN 100, ES_EVENT_TYPE_NOTIFY_CLOSE 20, "
                       + "ES_EVENT_TYPE_NOTIFY_CREATE 5, ES_EVENT_TYPE_NOTIFY_DUP 5")
    }
}
