//
//  CaptureSessionIndicatorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Indicators through a capture session
/// Pins the indicators a capture session stamps, on fake Endpoint Security clients: the configuration's set is in
/// place before the first event, a set ``CaptureSession/applyIndicators(_:)`` gives takes over from the next event,
/// `nil` stamps nothing, and each lane counts the events past the hit cap and the values compared only in part. A
/// `macmonitor` stream stamps its events too, `--no-mutes` or not.
final class CaptureSessionIndicatorTests: XCTestCase {
    /// The closed plist each test delivers, which "Plist modified" matches.
    private static let plist = "/Users/a/Library/LaunchAgents/com.example.agent.plist"
    /// Every close.
    private static let everyClose = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_CLOSE""#

    /// The configuration's set is the session's, and stamps the very first event.
    func testTheConfigurationsSetStampsTheFirstEvent() throws {
        let (session, factory, emitted) = try recordingSession(indicators: Self.shippedIndicators)
        defer { session.stop() }
        XCTAssertTrue(session.indicators === Self.shippedIndicators)
        factory.client(.file).deliver(closeMessage(modified: true, path: Self.plist, global: 1))
        let first = try decoded(emitted, count: 1)[0]
        XCTAssertTrue(try XCTUnwrap(first.indicators).hits.map(\.id).contains(try shippedID("Plist modified")))
        assertStamped(first.indicators)
    }

    /// A new set takes over from the next event, and `nil` stamps nothing from then on.
    func testALiveSwapTakesEffectForLaterEvents() throws {
        let (session, factory, emitted) = try recordingSession(indicators: Self.shippedIndicators)
        defer { session.stop() }
        let own = ownIndicator("Any close", Self.everyClose, severity: .low)
        factory.client(.file).deliver(closeMessage(modified: true, path: Self.plist, global: 1))
        XCTAssertTrue(session.applyIndicators(CompiledIndicators([own])))
        XCTAssertEqual(session.indicators?.count, 1)
        factory.client(.file).deliver(closeMessage(modified: true, path: Self.plist, global: 2))
        XCTAssertTrue(session.applyIndicators(nil))
        factory.client(.file).deliver(closeMessage(modified: true, path: Self.plist, global: 3))

        let events = try decoded(emitted, count: 3)
        XCTAssertEqual(events[0].indicators?.hits.map(\.id), try matcherHits(events[0]))
        XCTAssertEqual(events[1].indicators?.hits.map(\.id), [own.id])
        assertStamped(events[1].indicators, from: [own])
        XCTAssertNil(events[2].indicators)
        XCTAssertNil(session.indicators)
    }

    /// A stopped session takes no new set.
    func testAStoppedSessionTakesNoSet() throws {
        let (session, _, _) = try recordingSession(indicators: nil)
        session.stop()
        XCTAssertFalse(session.applyIndicators(Self.shippedIndicators))
        XCTAssertNil(session.indicators)
    }

    /// The file lane counts an event past the hit cap, and a value Foundation compared only part of: a path that
    /// isn't ASCII, past ``StringMatching/foundationLimit``, whose match beyond it is undetermined. Other lanes count
    /// nothing.
    func testTheLanesCountCappedEventsAndTruncations() throws {
        let capped = (0...CompiledIndicators.hitLimit).map { ownIndicator("Close \($0)", Self.everyClose) }
        let deep = ownIndicator("Deep", Self.everyClose + #" AND target_path CONTAINS[c] "needle""#)
        let (session, factory, emitted) = try recordingSession(indicators: CompiledIndicators([deep] + capped))
        defer { session.stop() }
        let long = "/tmp/\u{E9}" + String(repeating: "a", count: StringMatching.foundationLimit) + "needle"
        factory.client(.file).deliver(closeMessage(modified: false, path: long, global: 1))
        let event = try decoded(emitted, count: 1)[0]
        XCTAssertEqual(event.indicators?.hits.map(\.id), capped.prefix(CompiledIndicators.hitLimit).map(\.id))

        let file = try XCTUnwrap(session.statistics().first { $0.eventClass == .file })
        XCTAssertEqual(file.hitCappedEvents, 1)
        XCTAssertGreaterThan(file.truncatedEvaluations, 0)
        for lane in session.statistics() where lane.eventClass != .file {
            XCTAssertEqual(lane.hitCappedEvents, 0)
            XCTAssertEqual(lane.truncatedEvaluations, 0)
        }
    }

    /// The file lane counts an event whose scan budget ran out, and one with indicators undetermined, apart from the
    /// hit cap and the truncations: a non-ASCII path past the window, whose `ENDSWITH` costs more than the other
    /// fields' pool has, and whose record lists the rule as undetermined. An ordinary close after it, which lists
    /// none, and the other lanes count nothing more.
    func testTheLanesCountExhaustedAndUndeterminedEvents() throws {
        let ends = ownIndicator("Ends", Self.everyClose + #" AND target_path ENDSWITH[c] "needle""#)
        let (session, factory, emitted) = try recordingSession(indicators: CompiledIndicators([ends]))
        defer { session.stop() }
        let long = "/tmp/\u{E9}" + String(repeating: "a", count: StringMatching.foundationLimit) + "needle"
        factory.client(.file).deliver(closeMessage(modified: false, path: long, global: 1))
        factory.client(.file).deliver(closeMessage(modified: true, path: Self.plist, global: 2))
        let events = try decoded(emitted, count: 2)
        XCTAssertEqual(events.map { $0.indicators?.hits }, [[], []])
        XCTAssertEqual(events.map { $0.indicators_undetermined?.entries.map(\.hit.id) }, [[ends.id], nil])

        let file = try XCTUnwrap(session.statistics().first { $0.eventClass == .file })
        XCTAssertEqual(file.scanExhaustedEvents, 1)
        XCTAssertEqual(file.undeterminedEvents, 1)
        XCTAssertEqual(file.hitCappedEvents, 0)
        XCTAssertEqual(file.truncatedEvaluations, 1)
        for lane in session.statistics() where lane.eventClass != .file {
            XCTAssertEqual(lane.scanExhaustedEvents, 0)
            XCTAssertEqual(lane.undeterminedEvents, 0)
        }
    }

    /// A `--no-mutes` stream's events carry the verdicts of the Mac's indicator set, as Mac Monitor's do.
    func testAStreamStampsItsEvents() throws {
        let savedMutes = SavedMuteSet(testing: try makeMuteStore())
        let savedIndicators = try makeSavedIndicatorSet()
        let harness = StreamHarness(savedMutes: savedMutes, serializer: MessageSerializer(processPath: { _, _ in nil }),
                                    savedIndicators: savedIndicators)
        let reader = TestStreamReader()
        let connection = harness.connect(reader: reader)
        defer { connection.invalidate() }
        let request = StreamRequest(.stream, options: StreamOptions(events: ["ES_EVENT_TYPE_NOTIFY_CLOSE"],
                                                                    appliesSavedMutes: false))
        XCTAssertEqual(connection.send(request.encoded())?.status, .ok)
        let factory = try XCTUnwrap(harness.factories.first)
        factory.client(.file).deliver(closeMessage(modified: true, path: Self.plist, global: 1))
        XCTAssertTrue(waitUntil { reader.events.count == 1 })
        let event = try JSONDecoder().decode(Message.self, from: Data(try XCTUnwrap(reader.events.first).utf8))
        XCTAssertEqual(event.indicators?.hits.map(\.id), try matcherHits(event))
        XCTAssertFalse(try XCTUnwrap(event.indicators).hits.isEmpty)
        assertStamped(event.indicators)
    }
}


// MARK: - Helpers
extension CaptureSessionIndicatorTests {
    /// A recording session on fake clients that builds real events.
    ///
    /// - Parameter indicators: The configuration's set.
    /// - Returns: The session, its clients, and what it emits.
    /// - Throws: ``CaptureStartError`` if it couldn't start.
    func recordingSession(indicators: CompiledIndicators?) throws
        -> (CaptureSession, FakeEndpointSecurityClientFactory, EmittedEvents) {
        var configuration = CaptureConfiguration(label: "Test")
        configuration.indicators = indicators
        let factory = FakeEndpointSecurityClientFactory(), emitted = EmittedEvents()
        let session = try CaptureSession(configuration, clients: factory,
                                         serializer: MessageSerializer(processPath: { _, _ in nil }),
                                         sensorID: { "SENSOR" }, emit: emitted.append)
        session.isRecording = true
        return (session, factory, emitted)
    }

    /// What a session emitted, read as Mac Monitor decodes it.
    ///
    /// - Parameters:
    ///   - emitted: What it emitted.
    ///   - count: How many events to expect.
    /// - Returns: The events, in order.
    /// - Throws: A failure when there aren't that many, or the error decoding one.
    func decoded(_ emitted: EmittedEvents, count: Int) throws -> [Message] {
        let events = emitted.all
        guard events.count == count else { throw BenchmarkFailure("\(events.count) events, not \(count)") }
        return try events.map { try JSONDecoder().decode(Message.self, from: $0.json) }
    }
}
