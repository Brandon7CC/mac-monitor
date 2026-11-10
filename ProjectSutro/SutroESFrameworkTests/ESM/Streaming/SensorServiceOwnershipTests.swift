//
//  SensorServiceOwnershipTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Who owns Mac Monitor's event stream
/// Pins the Security Extension's side of Mac Monitor over real NSXPC connections: the first Mac Monitor to start
/// capture owns the event stream, a second is refused it and every change that needs it, a start Endpoint Security
/// refuses leaves no owner, the owner can redo its handshake, and only the owner going away stops capture, stops
/// following the saved sets, and says the stream is free, once.
final class SensorServiceOwnershipTests: XCTestCase {
    private var savedMutes = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))
    private var savedIndicators = SavedIndicatorSet(directory: URL(fileURLWithPath: "/nonexistent"), owner: getuid())
    private var commandLineAccess = CommandLineAccessStore()

    /// Saved sets in fresh directories, and command line access in its own suite.
    ///
    /// - Throws: If a directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        savedMutes = SavedMuteSet(testing: try makeMuteStore())
        savedIndicators = try makeSavedIndicatorSet()
        let suite = "SensorServiceOwnershipTests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        addTeardownBlock { defaults.removePersistentDomain(forName: suite) }
        commandLineAccess = CommandLineAccessStore(defaults: defaults)
    }

    /// A service on fake clients.
    ///
    /// - Parameter refusals: `es_new_client` refusals for each capture session, in order.
    /// - Returns: The harness.
    private func makeHarness(refusals: [[Int: NewClientResult]] = []) -> SensorServiceHarness {
        SensorServiceHarness(savedMutes: savedMutes, savedIndicators: savedIndicators,
                             commandLineAccess: commandLineAccess, refusals: refusals)
    }

    /// How many capture sessions follow each saved set.
    private var followers: [Int] {
        [savedMutes.followerCount, savedIndicators.followerCount]
    }

    /// Ask to record or not.
    ///
    /// - Parameters:
    ///   - connection: Mac Monitor's connection.
    ///   - enabled: Whether to record.
    /// - Returns: The answer.
    private func setRecording(_ connection: NSXPCConnection, _ enabled: Bool = true) -> Bool? {
        connection.sensor { $0.setRecording(enabled, reply: $1) }
    }

    /// The first Mac Monitor to start owns the event stream. A second is refused without starting capture, and can't
    /// record or change subscriptions, while the owner can. Both may read the subscriptions.
    func testTheFirstToStartOwnsTheStream() throws {
        let harness = makeHarness()
        let (first, second) = (harness.connect(), harness.connect())
        defer { [first, second].forEach { $0.invalidate() } }
        XCTAssertEqual(followers, [0, 0])

        XCTAssertEqual(first.handshake(recording: false), .success)
        let owner = try XCTUnwrap(harness.owner)
        XCTAssertTrue(owner === harness.connections.first)
        XCTAssertEqual(second.handshake(), .streamOwned)
        XCTAssertTrue(harness.owner === owner, "A refused start doesn't change the owner.")
        XCTAssertEqual(harness.factories.count, 1, "A refused start doesn't start capture.")
        XCTAssertEqual(harness.capture.recording, false, "A refused start doesn't change recording.")
        XCTAssertEqual(followers, [1, 1])

        XCTAssertEqual(setRecording(second), false)
        XCTAssertEqual(harness.capture.recording, false)
        XCTAssertEqual(setRecording(first), true)
        XCTAssertEqual(harness.capture.recording, true)

        let exit = "ES_EVENT_TYPE_NOTIFY_EXIT"
        XCTAssertEqual(second.sensor { $0.setSubscription(exit, enabled: false, reply: $1) }, false)
        XCTAssertEqual(second.sensor { $0.eventSubscriptions(reply: $1) }?.contains(exit), true)
        XCTAssertEqual(first.sensor { $0.setSubscription(exit, enabled: false, reply: $1) }, true)
        XCTAssertEqual(second.sensor { $0.eventSubscriptions(reply: $1) }?.contains(exit), false)
    }

    /// While someone owns the stream, only they may change the saved mute set, the indicator set, command line access,
    /// or install an update. Anyone may still read them and check for updates. While no one owns it, anyone may change
    /// them, as a Mac Monitor launched with `--deactivate-security-extension` installs an update.
    func testOnlyTheOwnerChangesWhatTheStreamControls() throws {
        let harness = makeHarness()
        let (first, second) = (harness.connect(), harness.connect())
        defer { [first, second].forEach { $0.invalidate() } }
        let add = MuteRequest(.add, [MuteFile.Entry(path: "/usr/bin/yes", type: "ES_MUTE_PATH_TYPE_PREFIX")])
        let mutes = { (connection: NSXPCConnection, request: MuteRequest) -> MuteReply? in
            connection.sensor { $0.mutes(request.encoded(), reply: $1) }.flatMap { MuteReply.decode($0) }
        }
        let access = { (connection: NSXPCConnection, level: CommandLineAccess) -> CommandLineAccessChange? in
            connection.sensor { $0.setCommandLineAccess(level.rawValue, reply: $1) }
                .flatMap(CommandLineAccessChange.init(rawValue:))
        }
        let indicators = { (connection: NSXPCConnection, request: IndicatorRequest) -> IndicatorReply? in
            connection.sensor { $0.indicators(request.encoded(), reply: $1) }.flatMap { IndicatorReply.decode($0) }
        }
        let close = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_CLOSE""#
        let addIndicator = { IndicatorRequest(.add, indicators: [self.ownIndicator(UUID().uuidString, close)]) }
        let install = { (connection: NSXPCConnection) -> String?? in connection.sensor { $0.installUpdate(reply: $1) } }

        /// Nobody owns it.
        XCTAssertEqual(access(second, .streaming), .done)
        XCTAssertEqual(mutes(second, MuteRequest(.list))?.access, .write)
        XCTAssertEqual(indicators(second, addIndicator())?.status, .ok)
        XCTAssertEqual(install(second), .some(nil))
        XCTAssertEqual(harness.updates.asked.installs, 1)

        XCTAssertEqual(first.handshake(), .success)
        XCTAssertEqual(second.handshake(), .streamOwned)
        let refused = try XCTUnwrap(mutes(second, add))
        XCTAssertEqual(refused.status, .refused)
        XCTAssertEqual(refused.access, .read)
        XCTAssertEqual(mutes(second, MuteRequest(.list))?.status, .ok)
        XCTAssertEqual(access(second, .streamingAndChanges), .streamOwned)
        XCTAssertEqual(second.sensor { $0.commandLineAccess(reply: $1) }, CommandLineAccess.streaming.rawValue)
        let refusedIndicators = try XCTUnwrap(indicators(second, addIndicator()))
        XCTAssertEqual(refusedIndicators.status, .refused)
        XCTAssertEqual(refusedIndicators.access, .read)
        XCTAssertEqual(indicators(second, IndicatorRequest(.list))?.status, .ok)
        XCTAssertEqual(install(second), .some(UpdateFailure.streamOwned.rawValue))
        guard case .upToDate? = second.sensor({ $0.checkForUpdate(reply: $1) }).map(UpdateCheck.decode) else {
            return XCTFail("A Mac Monitor that doesn't own the stream can check for updates.")
        }
        XCTAssertEqual(harness.updates.asked.installs, 1)
        XCTAssertEqual(harness.updates.asked.checks, 1)

        let owned = try XCTUnwrap(mutes(first, add))
        XCTAssertEqual(owned.status, .ok)
        XCTAssertEqual(owned.access, .write)
        XCTAssertEqual(access(first, .streamingAndChanges), .done)
        XCTAssertEqual(commandLineAccess.access, .streamingAndChanges)
        let ownedIndicators = try XCTUnwrap(indicators(first, addIndicator()))
        XCTAssertEqual(ownedIndicators.status, .ok)
        XCTAssertEqual(ownedIndicators.access, .write)
        XCTAssertEqual(install(first), .some(nil))
        XCTAssertEqual(harness.updates.asked.installs, 2)
    }

    /// An install's progress goes to the Mac Monitor that asked, ahead of the reply.
    func testAnInstallsProgressGoesToWhoAsked() throws {
        let harness = makeHarness()
        let (asker, other) = (RecordingAgent(), RecordingAgent())
        let (first, second) = (harness.connect(agent: asker), harness.connect(agent: other))
        defer { [first, second].forEach { $0.invalidate() } }
        XCTAssertEqual(first.handshake(), .success)
        XCTAssertEqual(second.handshake(), .streamOwned)

        let installed: String?? = first.sensor { $0.installUpdate(reply: $1) }
        XCTAssertEqual(installed, .some(nil))
        XCTAssertEqual(asker.updates, [.verifying])
        XCTAssertEqual(other.updates, [])
    }

    /// A start Endpoint Security refuses leaves no owner, no capture, nothing following the saved sets, and every
    /// client it made deleted, without saying the stream was released. Another Mac Monitor can then claim it, and the
    /// refused one can't record.
    func testARefusedStartLeavesNoOwner() throws {
        let harness = makeHarness(refusals: [[2: .tooManyClients]])
        let (first, second) = (harness.connect(), harness.connect())
        defer { [first, second].forEach { $0.invalidate() } }

        XCTAssertEqual(first.handshake(), .tooManyClients)
        XCTAssertNil(harness.owner)
        XCTAssertEqual(harness.capture.running, false)
        XCTAssertEqual(followers, [0, 0])
        let refused = try XCTUnwrap(harness.factories.first)
        XCTAssertEqual(refused.clients.count, 2)
        XCTAssertTrue(refused.clients.allSatisfy { $0.calls(.delete).count == 1 })
        XCTAssertEqual(harness.releases, 0)
        XCTAssertEqual(setRecording(first), false)

        XCTAssertEqual(second.handshake(), .success)
        XCTAssertTrue(harness.owner === harness.connections.last)
        XCTAssertEqual(setRecording(first), false)
        XCTAssertEqual(setRecording(second), true)
        XCTAssertEqual(first.handshake(), .streamOwned)
    }

    /// The owner can start again, as Mac Monitor does after the Security Extension says it's ready: capture keeps
    /// running, its Sensor ID is computed again, and recording follows the new handshake. Nothing new is started.
    func testTheOwnerRedoesItsHandshake() throws {
        let harness = makeHarness()
        let owner = harness.connect()
        defer { owner.invalidate() }

        XCTAssertEqual(owner.handshake(recording: false), .success)
        let session = try XCTUnwrap(harness.service.queue.sync { harness.service.capture })
        XCTAssertEqual(harness.sensorIDs, 1)
        XCTAssertEqual(owner.handshake(recording: true), .success)
        XCTAssertEqual(harness.capture.recording, true)
        XCTAssertEqual(owner.handshake(recording: false), .success)
        XCTAssertEqual(harness.capture.recording, false)

        XCTAssertTrue(harness.service.queue.sync { harness.service.capture } === session)
        XCTAssertEqual(harness.factories.count, 1)
        XCTAssertEqual(harness.sensorIDs, 3)
        XCTAssertEqual(followers, [1, 1])
        XCTAssertTrue(harness.factories[0].clients.allSatisfy { $0.calls(.delete).isEmpty })
    }

    /// Recorded events reach the owner and no one else.
    func testEventsReachOnlyTheOwner() throws {
        let harness = makeHarness()
        let (ownerAgent, otherAgent) = (RecordingAgent(), RecordingAgent())
        let (first, second) = (harness.connect(agent: ownerAgent), harness.connect(agent: otherAgent))
        defer { [first, second].forEach { $0.invalidate() } }
        XCTAssertEqual(first.handshake(), .success)
        XCTAssertEqual(second.handshake(), .streamOwned)

        let factory = try XCTUnwrap(harness.factories.first)
        (1...3).forEach { factory.client(.process).deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: $0)) }
        XCTAssertTrue(waitUntil { ownerAgent.received == ["1", "2", "3"] }, "\(ownerAgent.received)")
        XCTAssertEqual(otherAgent.received, [])
    }

    /// Another connection going away changes nothing. The owner's going away stops capture, deletes its clients,
    /// stops following the saved sets, and says the stream is free once. Then a new Mac Monitor can claim it.
    func testOnlyTheOwnerGoingAwayStopsCapture() throws {
        let harness = makeHarness()
        let (first, second, third) = (harness.connect(), harness.connect(), harness.connect())
        defer { third.invalidate() }
        XCTAssertEqual(first.handshake(), .success)
        XCTAssertEqual(second.handshake(), .streamOwned)
        let factory = try XCTUnwrap(harness.factories.first)

        second.invalidate()
        XCTAssertTrue(waitUntil { harness.invalidations == 1 }, "The service saw the refused connection go.")
        XCTAssertEqual(harness.releases, 0)
        XCTAssertEqual(setRecording(first), true)
        XCTAssertTrue(factory.clients.allSatisfy { $0.calls(.delete).isEmpty })
        XCTAssertEqual(followers, [1, 1])

        first.invalidate()
        XCTAssertTrue(waitUntil { harness.invalidations == 2 })
        XCTAssertEqual(harness.releases, 1)
        XCTAssertNil(harness.owner)
        XCTAssertEqual(harness.capture.running, false)
        XCTAssertTrue(factory.clients.allSatisfy { $0.calls(.delete).count == 1 })
        XCTAssertEqual(followers, [0, 0])

        XCTAssertEqual(third.handshake(), .success)
        XCTAssertTrue(harness.owner === harness.connections.last)
        XCTAssertEqual(harness.factories.count, 2)
        XCTAssertEqual(harness.releases, 1, "The release is said once.")
        XCTAssertEqual(followers, [1, 1])
    }
}
