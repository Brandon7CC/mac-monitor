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
    
    /// Deliver messages to one client.
    ///
    /// - Parameters:
    ///   - type: The messages' event type.
    ///   - numbers: Each message's `seq_num` and `global_seq_num`.
    ///   - client: The client's position in ``EventClass/allCases``.
    private func deliver(_ type: es_event_type_t, _ numbers: [(seq: UInt64, global: UInt64)], to client: Int) {
        for number in numbers {
            factory.clients[client].deliver(sequencedMessage(type, seq: number.seq, global: number.global))
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
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testGlobalGapsArePerClient() throws {
        let session = try makeSession(factory: factory)
        session.isRecording = true
        deliver(ES_EVENT_TYPE_NOTIFY_EXEC, [(1, 10), (2, 11), (5, 14)], to: 0)
        deliver(ES_EVENT_TYPE_NOTIFY_OPEN, [(1, 10), (2, 11), (3, 12)], to: 1)
        let process = try statistics(session, .process)
        XCTAssertEqual(process.messages, 3)
        XCTAssertEqual(process.dropped, 2)
        XCTAssertEqual(process.gaps, 1)
        XCTAssertEqual(process.droppedByType, ["ES_EVENT_TYPE_NOTIFY_EXEC": 2])
        let file = try statistics(session, .file)
        XCTAssertEqual(file.messages, 3)
        XCTAssertEqual(file.dropped, 0)
        XCTAssertEqual(file.subscribedEvents, session.subscribedEvents.filter {
            EventClassTable.eventClass(of: $0) == .file
        }.count)
    }
    
    /// Messages handed over while not recording are counted, so they're never mistaken for drops later.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testMessagesWhileNotRecordingAreNotDrops() throws {
        let session = try makeSession(factory: factory)
        deliver(ES_EVENT_TYPE_NOTIFY_EXIT, [(1, 1), (2, 2)], to: 0)
        session.isRecording = true
        deliver(ES_EVENT_TYPE_NOTIFY_EXIT, [(3, 3), (4, 4)], to: 0)
        let process = try statistics(session, .process)
        XCTAssertEqual(process.messages, 4)
        XCTAssertEqual(process.dropped, 0)
    }
    
    /// A drop report names the client and the types it lost, and only has drops since the last one.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testDropReportHasOnlyNewDrops() throws {
        let session = try makeSession(factory: factory)
        XCTAssertTrue(session.takeDropReport().isEmpty)
        deliver(ES_EVENT_TYPE_NOTIFY_OPEN, [(1, 1), (4, 4)], to: 1)
        XCTAssertEqual(session.takeDropReport(), [CaptureDropReport(eventClass: .file, dropped: 2,
                                                                    droppedByType: ["ES_EVENT_TYPE_NOTIFY_OPEN": 2])])
        XCTAssertTrue(session.takeDropReport().isEmpty)
        deliver(ES_EVENT_TYPE_NOTIFY_OPEN, [(5, 5)], to: 1)
        deliver(ES_EVENT_TYPE_NOTIFY_CLOSE, [(1, 7)], to: 1)
        deliver(ES_EVENT_TYPE_NOTIFY_MMAP, [(1, 1), (3, 3)], to: 2)
        XCTAssertEqual(session.takeDropReport(), [
            CaptureDropReport(eventClass: .file, dropped: 1, droppedByType: [:]),
            CaptureDropReport(eventClass: .memory, dropped: 1, droppedByType: ["ES_EVENT_TYPE_NOTIFY_MMAP": 1])
        ])
        XCTAssertEqual(try statistics(session, .file).dropped, 3)
    }
    
    /// Drops are logged at most once a second, and the report waits for the next chance.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testDropReportsAreRateLimited() throws {
        let session = try makeSession(factory: factory)
        let second = CaptureSession.dropReportInterval
        XCTAssertTrue(session.reportDrops(now: second).isEmpty)
        deliver(ES_EVENT_TYPE_NOTIFY_EXEC, [(1, 1), (3, 3)], to: 0)
        XCTAssertTrue(session.reportDrops(now: second + second / 2).isEmpty)
        XCTAssertEqual(session.reportDrops(now: 2 * second).map(\.dropped), [1])
        XCTAssertTrue(session.reportDrops(now: 4 * second).isEmpty)
    }
    
    /// A `global_seq_num` that repeats or goes backwards, which Endpoint Security should never send, is counted apart
    /// from drops.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testSequenceRegressionsAreCounted() throws {
        let session = try makeSession(factory: factory)
        deliver(ES_EVENT_TYPE_NOTIFY_EXIT, [(1, 5), (2, 5), (3, 4), (4, 5)], to: 0)
        let process = try statistics(session, .process)
        XCTAssertEqual(process.regressions, 2)
        XCTAssertEqual(process.dropped, 0)
        XCTAssertEqual(process.gaps, 0)
        XCTAssertEqual(try statistics(session, .file).regressions, 0)
    }
    
    /// Events that can't be serialized are counted, apart from drops.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testSerializationFailuresAreCounted() throws {
        let session = try makeSession(factory: factory, serializer: StubSerializer { _, _ in nil })
        session.isRecording = true
        deliver(ES_EVENT_TYPE_NOTIFY_EXIT, [(1, 1), (2, 2)], to: 0)
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
