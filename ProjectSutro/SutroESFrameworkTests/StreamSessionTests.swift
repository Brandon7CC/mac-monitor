//
//  StreamSessionTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Streams over XPC
/// Pins the Security Extension's side of `macmonitor` over a real NSXPC connection: a stream delivers its events, a
/// stop delivers everything captured before answering, streams are capped and refused cleanly, the saved mutes reach
/// a stream unless it asked for none, and a connection that goes away frees everything.
final class StreamSessionTests: XCTestCase {
    private var savedMutes = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))
    
    /// A saved set in a fresh directory.
    ///
    /// - Throws: If the directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        savedMutes = SavedMuteSet(testing: try makeMuteStore())
    }
    
    /// A stream request.
    ///
    /// - Parameters:
    ///   - events: `ES_EVENT_TYPE_NOTIFY_*` names.
    ///   - mutes: Apply the saved mutes?
    /// - Returns: The request's JSON.
    private func stream(_ events: [String] = ["ES_EVENT_TYPE_NOTIFY_EXIT"], mutes: Bool = true) -> Data {
        StreamRequest(.stream, options: StreamOptions(events: events, appliesSavedMutes: mutes)).encoded()
    }
    
    /// Deliver exit messages to a stream's process client.
    ///
    /// - Parameters:
    ///   - sequences: Their `global_seq_num`s.
    ///   - factory: The stream's client factory.
    private func deliverExits(_ sequences: ClosedRange<UInt64>, to factory: FakeEndpointSecurityClientFactory) {
        sequences.forEach { factory.clients[0].deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: $0)) }
    }
    
    /// A stream subscribes to what it asked for, delivers its events, and a stop answers with the summary, deletes the
    /// clients, and says they're free.
    func testAStreamDeliversItsEvents() throws {
        let harness = StreamHarness(savedMutes: savedMutes)
        let reader = TestStreamReader()
        let connection = harness.connect(reader: reader)
        defer { connection.invalidate() }
        
        let started = try XCTUnwrap(connection.send(stream()))
        XCTAssertEqual(started.status, .ok)
        XCTAssertEqual(started.sensorVersion, "2.2.0 (1)")
        XCTAssertEqual(started.stream?.events, ["ES_EVENT_TYPE_NOTIFY_EXIT"])
        XCTAssertEqual(started.stream?.savedMutes, MuteList.testDefault.count)
        let factory = try XCTUnwrap(harness.factories.first)
        XCTAssertEqual(factory.clients[0].calls(.subscribe), [.subscribe([ES_EVENT_TYPE_NOTIFY_EXIT])])
        
        deliverExits(1...3, to: factory)
        XCTAssertTrue(waitUntil { reader.events == ["1", "2", "3"] })
        let stopped = try XCTUnwrap(connection.send(StreamRequest(.stop).encoded()))
        XCTAssertEqual(stopped.summary, StreamSummary(captured: 3, delivered: 3, droppedByEndpointSecurity: 0,
                                                      droppedWhileBehind: 0, skippedWhilePaused: 0, pauses: 0))
        XCTAssertTrue(waitUntil { factory.clients.allSatisfy { $0.calls(.delete).count == 1 } })
        /// The slot is freed, and the clients said to be free, just after they're deleted.
        XCTAssertTrue(waitUntil { harness.service.slots.count == 0 })
        XCTAssertTrue(waitUntil { harness.releases == 1 })
    }
    
    /// A stop answers only once every event captured before it has been delivered, including events still queued in
    /// Endpoint Security when it arrived.
    func testAStopDeliversEverythingCapturedFirst() throws {
        let harness = StreamHarness(savedMutes: savedMutes)
        let reader = TestStreamReader()
        let connection = harness.connect(reader: reader)
        defer { connection.invalidate() }
        XCTAssertEqual(connection.send(stream())?.status, .ok)
        let factory = try XCTUnwrap(harness.factories.first)
        factory.clients.forEach { $0.holdSyncs() }
        deliverExits(1...2, to: factory)
        
        let stopped = expectation(description: "stopped")
        connection.sendAsync(StreamRequest(.stop).encoded()) { reply in
            XCTAssertEqual(reply?.summary?.delivered, 3)
            XCTAssertEqual(reader.events, ["1", "2", "3"], "Every event arrives before the stop's answer.")
            stopped.fulfill()
        }
        XCTAssertTrue(waitUntil { factory.clients.allSatisfy { !$0.calls(.sync).isEmpty } })
        /// Queued ahead of the sync marker.
        deliverExits(3...3, to: factory)
        factory.clients.forEach { $0.releaseSyncs() }
        wait(for: [stopped], timeout: 5)
    }
    
    /// No more streams run than the cap. A refused connection can stream once a slot frees, and a connection that
    /// goes away frees its slot and deletes its clients.
    func testStreamsAreCapped() throws {
        let harness = StreamHarness(savedMutes: savedMutes, capacity: 2)
        let connections = (0..<3).map { _ in harness.connect(reader: TestStreamReader()) }
        defer { connections.forEach { $0.invalidate() } }
        XCTAssertEqual(connections[0].send(stream())?.status, .ok)
        XCTAssertEqual(connections[1].send(stream())?.status, .ok)
        let refused = try XCTUnwrap(connections[2].send(stream()))
        XCTAssertEqual(refused.status, .sessionLimit)
        XCTAssertNotNil(refused.problem)
        
        connections[0].invalidate()
        XCTAssertTrue(waitUntil { harness.service.slots.count == 1 })
        XCTAssertTrue(harness.factories[0].clients.allSatisfy { $0.calls(.delete).count == 1 })
        XCTAssertEqual(connections[2].send(stream())?.status, .ok)
    }
    
    /// A connection streams once.
    func testOneStreamAConnection() {
        let harness = StreamHarness(savedMutes: savedMutes)
        let connection = harness.connect(reader: TestStreamReader())
        defer { connection.invalidate() }
        XCTAssertEqual(connection.send(stream())?.status, .ok)
        XCTAssertEqual(connection.send(stream())?.status, .alreadyStreaming)
        XCTAssertEqual(connection.send(StreamRequest(.stop).encoded())?.status, .ok)
        XCTAssertEqual(connection.send(stream())?.status, .alreadyStreaming)
        XCTAssertEqual(harness.factories.count, 1)
    }
    
    /// Endpoint Security's refusals have their own statuses, and free the slot. No clients were held, so none are said
    /// to be free.
    func testEndpointSecurityRefusalsAreAnswered() {
        let refusals: [(NewClientResult, StreamReply.Status)] = [
            (.tooManyClients, .clientLimit), (.notPermitted, .notPermitted), (.internalSubsystem, .failed)
        ]
        for (refusal, status) in refusals {
            let harness = StreamHarness(savedMutes: savedMutes, refusals: [1: refusal])
            let connection = harness.connect(reader: TestStreamReader())
            let reply = connection.send(stream())
            XCTAssertEqual(reply?.status, status, "\(refusal)")
            XCTAssertNotNil(reply?.problem)
            XCTAssertEqual(harness.service.slots.count, 0)
            connection.invalidate()
            XCTAssertEqual(harness.releases, 0)
        }
    }
    
    /// Malformed, newer, and impossible requests are answered, not fatal, and start nothing.
    func testBadRequestsAreAnswered() {
        let harness = StreamHarness(savedMutes: savedMutes)
        let connection = harness.connect(reader: TestStreamReader())
        defer { connection.invalidate() }
        XCTAssertEqual(connection.send(Data("garbage".utf8))?.status, .invalid)
        XCTAssertEqual(connection.send(Data(#"{"version":1,"kind":"schema"}"#.utf8))?.status, .unsupported)
        XCTAssertEqual(connection.send(Data(#"{"version":9,"kind":"stream"}"#.utf8))?.status, .unsupported)
        let auth = connection.send(stream(["ES_EVENT_TYPE_AUTH_EXEC"]))
        XCTAssertEqual(auth?.status, .invalid)
        XCTAssertEqual(auth?.problem, "ES_EVENT_TYPE_AUTH_EXEC isn't an event macmonitor can stream on this Mac.")
        XCTAssertEqual(connection.send(StreamRequest(.hello).encoded()),
                       StreamReply(.ok, sensorVersion: "2.2.0 (1)"))
        XCTAssertTrue(harness.factories.isEmpty)
        XCTAssertEqual(connection.send(stream())?.status, .ok, "A bad request doesn't use up the stream.")
    }
    
    /// A caller the service doesn't admit (not root) is refused stream and mute requests alike.
    func testNonRootCallersAreRefused() {
        let harness = StreamHarness(savedMutes: savedMutes, admits: false)
        let connection = harness.connect(reader: TestStreamReader())
        defer { connection.invalidate() }
        XCTAssertEqual(connection.send(stream())?.status, .refused)
        XCTAssertEqual(connection.sendMutes(MuteRequest(.reset))?.status, .refused)
        XCTAssertTrue(harness.factories.isEmpty)
    }
    
    /// A `--no-mutes` stream starts with no path mutes and ignores changes; a stream with them gets each change, made
    /// through `macmonitor`'s own mute requests, and is told who made it and how.
    func testTheSavedMutesReachStreamsThatAskForThem() throws {
        let harness = StreamHarness(savedMutes: savedMutes)
        let (followingReader, bareReader) = (TestStreamReader(), TestStreamReader())
        let following = harness.connect(reader: followingReader)
        let bare = harness.connect(reader: bareReader)
        defer { [following, bare].forEach { $0.invalidate() } }
        XCTAssertEqual(following.send(stream())?.stream?.savedMutes, MuteList.testDefault.count)
        let started = try XCTUnwrap(bare.send(stream(mutes: false)))
        XCTAssertNotNil(started.stream)
        XCTAssertNil(started.stream?.savedMutes)
        let (followingClients, bareClients) = (harness.factories[0].clients, harness.factories[1].clients)
        XCTAssertTrue(bareClients.allSatisfy { $0.calls(.setPathMute).isEmpty })
        
        let entry = MuteFile.Entry(path: "/usr/bin/yes", type: "ES_MUTE_PATH_TYPE_LITERAL")
        XCTAssertEqual(bare.sendMutes(MuteRequest(.add, [entry]))?.status, .ok)
        let mute = FakeEndpointSecurityClient.Call.setPathMute(
            PathMute(path: "/usr/bin/yes", type: ES_MUTE_PATH_TYPE_LITERAL), muted: true)
        XCTAssertTrue(waitUntil { followingClients.allSatisfy { $0.calls.last == mute } })
        XCTAssertTrue(bareClients.allSatisfy { $0.calls(.setPathMute).isEmpty })
        XCTAssertTrue(waitUntil { !followingReader.changes.isEmpty })
        XCTAssertEqual(followingReader.changes, [MuteSetChange(caller: "macmonitor (pid \(getpid()))", added: 1,
                                                               removed: 0, changed: 0,
                                                               mutes: MuteList.testDefault.count + 1)])
        XCTAssertEqual(bareReader.changes, [])
    }
    
    /// A reader that stops replying makes the stream pause capture instead of buffering without bound; what was
    /// dropped and skipped is counted, and once the reader catches up the stream carries on.
    func testABehindReaderPausesTheStream() throws {
        let harness = StreamHarness(savedMutes: savedMutes)
        let reader = TestStreamReader()
        let connection = harness.connect(reader: reader)
        defer { connection.invalidate() }
        reader.holdReplies()
        XCTAssertEqual(connection.send(stream(mutes: false))?.status, .ok)
        let factory = try XCTUnwrap(harness.factories.first)
        let limits = EventBatcher.Limits.commandLine
        let inFlight = UInt64(limits.maxBatchesInFlight * limits.batchSize)
        deliverExits(1...inFlight, to: factory)
        XCTAssertTrue(waitUntil { reader.heldCount == limits.maxBatchesInFlight })
        /// One more than fits pauses capture: it's dropped.
        let overflow = inFlight + UInt64(limits.memoryLimit) + 1
        deliverExits((inFlight + 1)...overflow, to: factory)
        /// Answered on the stream's queue after every event before it, so capture is paused by then.
        XCTAssertEqual(connection.send(StreamRequest(.hello).encoded())?.status, .ok)
        deliverExits((overflow + 1)...(overflow + 1_000), to: factory)
        
        reader.releaseReplies()
        XCTAssertTrue(waitUntil {
            reader.releaseReplies()
            return reader.events.count >= limits.memoryLimit + Int(inFlight)
        })
        let summary = try XCTUnwrap(connection.send(StreamRequest(.stop).encoded())?.summary)
        XCTAssertEqual(summary.pauses, 1)
        XCTAssertEqual(summary.droppedWhileBehind, 1)
        XCTAssertEqual(summary.skippedWhilePaused, 1_000)
        XCTAssertEqual(summary.delivered, reader.events.count)
        XCTAssertEqual(summary.captured, summary.delivered + summary.droppedWhileBehind)
    }
}
