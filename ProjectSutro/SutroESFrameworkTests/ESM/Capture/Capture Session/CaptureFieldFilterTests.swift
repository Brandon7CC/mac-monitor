//
//  CaptureFieldFilterTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Field filters in a capture session
/// Pins how a capture session leaves out the messages a ``FieldFilter`` turns away: counted once, never serialized,
/// never a drop or a skip, and only for the filtered event.
final class CaptureFieldFilterTests: XCTestCase {
    private let factory = FakeEndpointSecurityClientFactory()
    private let emitted = EmittedEvents()
    /// The `global_seq_num` of every message the serializer was handed.
    private let serialized = Recorded<UInt64>()

    /// A session on fake clients that leaves out unmodified closes unless told otherwise, with a serializer that
    /// records what it's handed.
    ///
    /// - Parameter filters: The field filters.
    /// - Returns: The session.
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    private func makeFilteredSession(_ filters: Set<FieldFilter> = [.modifiedCloses]) throws -> CaptureSession {
        var configuration = CaptureConfiguration(label: "Test")
        configuration.fieldFilters = filters
        let serialized = serialized
        let serializer = StubSerializer { message, _ in
            serialized.append(message.pointee.global_seq_num)
            return Data("\(message.pointee.global_seq_num)".utf8)
        }
        return try makeSession(configuration, factory: factory, serializer: serializer, emitted: emitted)
    }

    /// Hand the file client closes, numbered in order.
    ///
    /// - Parameters:
    ///   - modified: Each close's `modified`.
    ///   - first: The first close's `seq_num` and `global_seq_num`.
    private func deliverCloses(_ modified: [Bool], from first: UInt64 = 1) {
        for (offset, modified) in modified.enumerated() {
            let number = first + UInt64(offset)
            factory.client(.file).deliver(closeMessage(modified: modified, seq: number, global: number))
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

    /// An unmodified close is counted as a message and as left out, and nothing else: it never reaches the
    /// serializer, and its numbers are no gap.
    func testAnUnmodifiedCloseIsLeftOut() throws {
        let session = try makeFilteredSession()
        session.isRecording = true
        deliverCloses([false])
        let file = try statistics(session, .file)
        XCTAssertEqual(file.messages, 1)
        XCTAssertEqual(file.fieldFiltered, 1)
        XCTAssertEqual(file.dropped, 0)
        XCTAssertEqual(file.gaps, 0)
        XCTAssertEqual(file.serializationFailures, 0)
        XCTAssertEqual(emitted.all.count, 0)
        XCTAssertEqual(serialized.all, [])
        XCTAssertEqual(session.skippedMessages, 0)
    }

    /// A modified close is emitted. Left-out closes between them make no drop: the session saw every number.
    func testModifiedClosesAreEmitted() throws {
        let session = try makeFilteredSession()
        session.isRecording = true
        deliverCloses([true, false, false, true])
        XCTAssertEqual(emitted.globalSequences(of: .file), [1, 4])
        XCTAssertEqual(serialized.all, [1, 4])
        XCTAssertEqual(try statistics(session, .file).dropped, 0)
        XCTAssertEqual(session.fieldFilteredMessages, 2)
    }

    /// Without field filters every close is emitted.
    func testNoFiltersEmitEveryClose() throws {
        let session = try makeFilteredSession([])
        session.isRecording = true
        deliverCloses([true, false])
        XCTAssertEqual(emitted.globalSequences(of: .file), [1, 2])
        XCTAssertEqual(session.fieldFilteredMessages, 0)
        XCTAssertEqual(session.fieldFilters, [])
    }

    /// Turning the filter off or on takes effect from the next message, and the session says which are on. Once
    /// stopped, it refuses.
    func testTheFilterChangesLive() throws {
        let session = try makeFilteredSession()
        session.isRecording = true
        XCTAssertEqual(session.fieldFilters, [.modifiedCloses])
        deliverCloses([false])
        XCTAssertTrue(session.setFieldFilter(.modifiedCloses, enabled: false))
        XCTAssertEqual(session.fieldFilters, [])
        deliverCloses([false], from: 2)
        XCTAssertTrue(session.setFieldFilter(.modifiedCloses, enabled: true))
        XCTAssertEqual(session.fieldFilters, [.modifiedCloses])
        deliverCloses([false, true], from: 3)
        XCTAssertEqual(emitted.globalSequences(of: .file), [2, 4])
        XCTAssertEqual(session.fieldFilteredMessages, 2)
        session.stop()
        XCTAssertFalse(session.setFieldFilter(.modifiedCloses, enabled: false))
        XCTAssertEqual(session.fieldFilters, [.modifiedCloses])
    }

    /// While not recording, an unmodified close is left out and a modified one is skipped: each message lands in one
    /// count, so a stream never reports a left-out close as lost while paused.
    func testWhileNotRecordingLeftOutIsNotSkipped() throws {
        let session = try makeFilteredSession()
        deliverCloses([false, true, false, true, true])
        XCTAssertEqual(session.fieldFilteredMessages, 2)
        XCTAssertEqual(session.skippedMessages, 3)
        XCTAssertEqual(session.skippedMessages + session.fieldFilteredMessages, 5)
        XCTAssertEqual(serialized.all, [])
    }

    /// The filter checks only closes: opens, execs and mmaps on any client are emitted as before.
    func testOtherEventsAreUnaffected() throws {
        let session = try makeFilteredSession()
        session.isRecording = true
        factory.client(.file).deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_OPEN, seq: 1, global: 1))
        factory.client(.process).deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXEC, seq: 1, global: 1))
        factory.client(.memory).deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_MMAP, seq: 1, global: 1))
        XCTAssertEqual(emitted.all.map(\.eventClass), [.file, .process, .memory])
        XCTAssertEqual(session.fieldFilteredMessages, 0)
    }

    /// Only the client serving close counts what the filter left out, by event name. The session adds them up.
    func testOnlyTheFileLaneCountsLeftOutCloses() throws {
        let session = try makeFilteredSession()
        session.isRecording = true
        deliverCloses([false, false, true])
        for lane in session.statistics() {
            XCTAssertEqual(lane.fieldFiltered, lane.eventClass == .file ? 2 : 0, lane.eventClass.rawValue)
            XCTAssertEqual(lane.fieldFilteredByType, lane.eventClass == .file ? ["ES_EVENT_TYPE_NOTIFY_CLOSE": 2] : [:])
        }
        XCTAssertEqual(session.fieldFilteredByType(), ["ES_EVENT_TYPE_NOTIFY_CLOSE": 2])
    }

    /// A file changed only through a writable mapping closes unmodified, and is left out: the strict rule, pinned on
    /// purpose. Its mapping shows as an mmap event.
    func testAWritableMappingAloneIsLeftOut() throws {
        let session = try makeFilteredSession()
        session.isRecording = true
        factory.client(.file).deliver(closeMessage(modified: false, wasMappedWritable: true, seq: 1, global: 1))
        XCTAssertEqual(session.fieldFilteredMessages, 1)
        XCTAssertEqual(emitted.all.count, 0)
    }

    /// A closed lane counts messages, but leaves nothing out: it admits nothing at all.
    func testAClosedLaneCountsNothingLeftOut() throws {
        let session = try makeFilteredSession()
        session.isRecording = true
        session.lanes.forEach { $0.close() }
        deliverCloses([false, true])
        XCTAssertEqual(session.fieldFilteredMessages, 0)
        XCTAssertEqual(try statistics(session, .file).messages, 2)
        XCTAssertEqual(emitted.all.count, 0)
    }

    /// The filter is in place before the clients subscribe: a close Endpoint Security hands over while the session is
    /// still subscribing, before it has started, is already left out rather than skipped.
    func testTheFilterIsInPlaceBeforeSubscribing() throws {
        let close = closeMessage(modified: false, seq: 1, global: 1)
        factory.onSubscribe = { client, events in
            if events.contains(ES_EVENT_TYPE_NOTIFY_CLOSE) { client.deliver(close) }
        }
        let session = try makeFilteredSession()
        XCTAssertEqual(try statistics(session, .file).messages, 1)
        XCTAssertEqual(session.fieldFilteredMessages, 1)
        XCTAssertEqual(session.skippedMessages, 0)
    }
}
