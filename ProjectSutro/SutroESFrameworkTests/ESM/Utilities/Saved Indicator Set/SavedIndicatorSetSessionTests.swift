//
//  SavedIndicatorSetSessionTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import Combine
@testable import SutroESFramework


// MARK: - Sessions following the Mac's indicator set
/// Pins how the Mac's indicator set reaches capture, as Mac Monitor's session follows it in the Security Extension:
/// a session starts with the set, gets each change from its next event on, and nothing once it stops following. Who
/// may change the set from Mac Monitor follows the saved mute set's rule.
final class SavedIndicatorSetSessionTests: XCTestCase {
    /// Lets a follower closure reach a session made after it.
    private final class SessionBox {
        var session: CaptureSession?
    }

    /// Every close.
    private static let everyClose = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_CLOSE""#
    /// A closed plist, which "Plist modified" matches.
    private static let plist = "/Users/a/Library/LaunchAgents/com.example.agent.plist"

    /// A recording session following a set the way the Security Extension's does: the set read and followed at once,
    /// then given to the configuration. The follower applies changes synchronously, as the test drives the session
    /// from no other queue.
    ///
    /// - Parameter set: The indicator set.
    /// - Returns: The session, its clients, what it emits, and the subscription.
    /// - Throws: ``CaptureStartError`` if it couldn't start.
    private func follower(of set: SavedIndicatorSet) throws
        -> (CaptureSession, FakeEndpointSecurityClientFactory, EmittedEvents, AnyCancellable) {
        let box = SessionBox()
        let (compiled, subscription) = set.follow { box.session?.applyIndicators($0) }
        var configuration = CaptureConfiguration(label: "Test")
        configuration.indicators = compiled
        let factory = FakeEndpointSecurityClientFactory(), emitted = EmittedEvents()
        let session = try CaptureSession(configuration, clients: factory,
                                         serializer: MessageSerializer(processPath: { _, _ in nil }),
                                         sensorID: { "SENSOR" }, emit: emitted.append)
        session.isRecording = true
        box.session = session
        return (session, factory, emitted, subscription)
    }

    /// The hits of the events a session emitted, by indicator name.
    ///
    /// - Parameter emitted: What it emitted.
    /// - Returns: Each event's hits' names, in order.
    /// - Throws: The error decoding an event.
    private func hitNames(_ emitted: EmittedEvents) throws -> [[String]] {
        try emitted.all.map { try JSONDecoder().decode(Message.self, from: $0.json).indicators?.hits.map(\.name) ?? [] }
    }

    /// A following session starts with the set loaded, and each change reaches it before its next event, severity
    /// and all. The shipped set stamps the first plist, the own indicator the next.
    func testAFollowingSessionGetsEachChange() throws {
        let set = try makeSavedIndicatorSet()
        let (session, factory, emitted, subscription) = try follower(of: set)
        defer { session.stop(); subscription.cancel() }
        XCTAssertTrue(session.indicators === set.current)
        factory.client(.file).deliver(closeMessage(modified: true, path: Self.plist, global: 1))

        let own = ownIndicator("Any close", Self.everyClose, severity: .high)
        XCTAssertEqual(set.send(IndicatorRequest(.replace, indicators: [own])).status, .ok)
        XCTAssertTrue(session.indicators === set.current)
        factory.client(.file).deliver(closeMessage(modified: true, path: Self.plist, global: 2))

        let names = try hitNames(emitted)
        XCTAssertTrue(names[0].contains("Plist modified"), "\(names[0])")
        XCTAssertEqual(names[1], ["Any close"])
        let hit = try JSONDecoder().decode(Message.self, from: emitted.all[1].json).indicators?.hits.first
        XCTAssertEqual(hit?.severity, .high)
        XCTAssertEqual(hit?.evaluated_by, .securityExtension)
        XCTAssertEqual(hit?.isDefault, false)
    }

    /// A session that stopped following gets no later change.
    func testASessionThatStopsFollowingKeepsItsSet() throws {
        let set = try makeSavedIndicatorSet()
        let (session, _, _, subscription) = try follower(of: set)
        defer { session.stop() }
        let before = set.current
        subscription.cancel()
        set.waitUntilIdle()
        set.send(IndicatorRequest(.replace, indicators: [ownIndicator("Any close", Self.everyClose)]))
        XCTAssertTrue(session.indicators === before)
    }

    /// Each follower gets each change, in the order they started following.
    func testFollowersAreToldInOrder() throws {
        let set = try makeSavedIndicatorSet()
        let order = Recorded<Int>()
        let subscriptions = (0..<3).map { index in set.follow { _ in order.append(index) }.1 }
        defer { subscriptions.forEach { $0.cancel() } }
        set.send(IndicatorRequest(.add, indicators: [ownIndicator("Any close", Self.everyClose)]))
        set.send(IndicatorRequest(.remove, ids: [Indicator.defaults[0].id]))
        XCTAssertEqual(order.all, [0, 1, 2, 0, 1, 2])
    }

    /// Mac Monitor's access to the set is the saved mute set's: a Mac Monitor that controls the event stream may
    /// change it, whoever its user is, and any other only lists it.
    func testMacMonitorsAccessFollowsTheMuteRule() throws {
        let set = try makeSavedIndicatorSet()
        let owner = FakePeer(euid: 501), standardUser = FakePeer(euid: 502), other = FakePeer(euid: 501)
        let add = IndicatorRequest(.add, indicators: [ownIndicator("Any close", Self.everyClose)])
        XCTAssertEqual(set.send(add, access: MuteAccess.app(other, owner: owner)).status, .refused)
        XCTAssertEqual(set.send(add, access: MuteAccess.app(nil, owner: nil)).status, .refused)
        XCTAssertEqual(set.send(IndicatorRequest(.list), access: MuteAccess.app(other, owner: owner)).status, .ok)
        XCTAssertEqual(set.send(add, access: MuteAccess.app(standardUser, owner: nil)).status, .ok)
        XCTAssertEqual(set.send(IndicatorRequest(.remove, ids: [add.indicators[0].id]),
                                access: MuteAccess.app(owner, owner: owner)).status, .ok)
    }
}
