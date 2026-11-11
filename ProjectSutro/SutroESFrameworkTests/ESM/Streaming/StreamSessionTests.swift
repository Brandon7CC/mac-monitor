//
//  StreamSessionTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
import os
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
        sequences.forEach { factory.client(.process).deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: $0)) }
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
        XCTAssertEqual(started.sensorVersion, "3.0.0 (1)")
        XCTAssertEqual(started.stream?.events, ["ES_EVENT_TYPE_NOTIFY_EXIT"])
        XCTAssertEqual(started.stream?.savedMutes, MuteList.testDefault.count)
        let factory = try XCTUnwrap(harness.factories.first)
        XCTAssertEqual(factory.client(.process).calls(.subscribe), [.subscribe([ES_EVENT_TYPE_NOTIFY_EXIT])])
        
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
                       StreamReply(status: .ok, sensorVersion: "3.0.0 (1)"))
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

    /// A stream that began while its caller was allowed keeps its stop once the caller isn't: the stop is answered,
    /// with what the stream captured, where a new stream is refused. Refusing it cut the stream off undrained.
    func testAStopIsAnsweredAfterAccessIsNarrowed() {
        let allowed = OSAllocatedUnfairLock(initialState: true)
        let harness = StreamHarness(savedMutes: savedMutes, admitting: { _ in
            allowed.withLock { $0 } ? .everything : .refused(CommandLineAccess.needsRoot)
        })
        let connection = harness.connect(reader: TestStreamReader())
        defer { connection.invalidate() }
        XCTAssertEqual(connection.send(stream())?.status, .ok)
        allowed.withLock { $0 = false }
        let stopped = connection.send(StreamRequest(.stop).encoded())
        XCTAssertEqual(stopped?.status, .ok)
        XCTAssertNotNil(stopped?.summary)
        let other = harness.connect(reader: TestStreamReader())
        defer { other.invalidate() }
        XCTAssertEqual(other.send(stream())?.status, .refused)
    }
    
    /// Without root, the live rule decides each request by the level as it stands: refused at the default, streaming
    /// and listing the saved mute set but not changing it once streaming is allowed, and changing it too once changes
    /// are. Each reply says what the caller may do, and the refusals say why.
    func testACallerWithoutRootGetsWhatTheLevelAllows() throws {
        try XCTSkipIf(geteuid() == 0, "The test process is root, which may always do everything.")
        let level = OSAllocatedUnfairLock(initialState: CommandLineAccess.rootOnly)
        let admitting = StreamService.granting { level.withLock { $0 } }
        let harness = StreamHarness(savedMutes: savedMutes, admitting: admitting)
        let add = MuteRequest(.add, [MuteFile.Entry(path: "/usr/bin/yes", type: "ES_MUTE_PATH_TYPE_PREFIX")])
        let refused = harness.connect(reader: TestStreamReader())
        defer { refused.invalidate() }
        XCTAssertEqual(refused.send(stream()), StreamReply(status: .refused, problem: CommandLineAccess.needsRoot,
                                                           sensorVersion: "3.0.0 (1)"))
        XCTAssertEqual(refused.sendMutes(MuteRequest(.list))?.problems, [CommandLineAccess.needsRoot])
        
        level.withLock { $0 = .streaming }
        XCTAssertEqual(refused.sendMutes(MuteRequest(.list))?.access, .list, "The next request sees the change")
        let changing = refused.sendMutes(add)
        XCTAssertEqual(changing?.status, .refused)
        XCTAssertEqual(changing?.problems, [CommandLineAccess.needsChanges])
        XCTAssertEqual(refused.send(stream())?.status, .ok)
        
        level.withLock { $0 = .streamingAndChanges }
        let changed = refused.sendMutes(add)
        XCTAssertEqual(changed?.status, .ok)
        XCTAssertEqual(changed?.access, .write)
        XCTAssertEqual(harness.factories.count, 1)
    }
    
    /// A `--no-mutes` stream starts with no path mutes and ignores changes. A stream with them gets each change, made
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
    
    /// A reader that stops replying makes the stream pause capture instead of buffering without bound. What was
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


// MARK: - Field filters
extension StreamSessionTests {
    /// A stream request that asks for the close filter.
    ///
    /// - Parameter events: `ES_EVENT_TYPE_NOTIFY_*` names.
    /// - Returns: The request's JSON.
    private func filteredStream(_ events: [String]) -> Data {
        StreamRequest(.stream, options: StreamOptions(events: events, appliesSavedMutes: false,
                                                      fieldFilters: [FieldFilter.modifiedCloses.rawValue])).encoded()
    }
    
    /// Deliver closes to a stream's file client, numbered in order.
    ///
    /// - Parameters:
    ///   - modified: Each close's `modified`.
    ///   - first: The first close's `seq_num` and `global_seq_num`.
    ///   - factory: The stream's client factory.
    private func deliverCloses(_ modified: [Bool], from first: UInt64 = 1,
                               to factory: FakeEndpointSecurityClientFactory) {
        for (offset, modified) in modified.enumerated() {
            let number = first + UInt64(offset)
            factory.client(.file).deliver(closeMessage(modified: modified, seq: number, global: number))
        }
    }
    
    /// A stream with the close filter delivers only modified closes, echoes the filter it applied, and counts what it
    /// left out, never as a drop.
    func testAFilteredStreamLeavesOutUnmodifiedCloses() throws {
        let harness = StreamHarness(savedMutes: savedMutes)
        let reader = TestStreamReader()
        let connection = harness.connect(reader: reader)
        defer { connection.invalidate() }
        let started = try XCTUnwrap(connection.send(filteredStream(["ES_EVENT_TYPE_NOTIFY_CLOSE"])))
        XCTAssertEqual(started.stream?.fieldFilters, ["ES_EVENT_TYPE_NOTIFY_CLOSE.modified"])
        deliverCloses([true, false, true], to: try XCTUnwrap(harness.factories.first))
        XCTAssertTrue(waitUntil { reader.events == ["1", "3"] }, "\(reader.events)")
        let summary = try XCTUnwrap(connection.send(StreamRequest(.stop).encoded())?.summary)
        XCTAssertEqual(summary.delivered, 2)
        XCTAssertEqual(summary.fieldFiltered, ["ES_EVENT_TYPE_NOTIFY_CLOSE": 1])
        XCTAssertEqual(summary.droppedByEndpointSecurity, 0)
        XCTAssertEqual(summary.skippedWhilePaused, 0)
    }
    
    /// A request without field filters, as `macmonitor` 3.0.0 sends, gets 3.0.0's stream: no echo, no count, and no
    /// close among the defaults.
    func testA300RequestGetsA300Stream() throws {
        let harness = StreamHarness(savedMutes: savedMutes)
        let named = harness.connect(reader: TestStreamReader())
        let defaults = harness.connect(reader: TestStreamReader())
        defer { [named, defaults].forEach { $0.invalidate() } }
        XCTAssertNil(try XCTUnwrap(named.send(stream())).stream?.fieldFilters)
        XCTAssertNil(try XCTUnwrap(named.send(StreamRequest(.stop).encoded())?.summary).fieldFiltered)
        let all = try XCTUnwrap(defaults.send(StreamRequest(.stream, options: StreamOptions()).encoded())?.stream)
        XCTAssertFalse(all.events.contains("ES_EVENT_TYPE_NOTIFY_CLOSE"))
        XCTAssertNil(all.fieldFilters)
    }
    
    /// While capture is paused, an unmodified close is left out rather than skipped, so it's never counted as lost.
    func testLeftOutClosesWhilePausedAreNotSkipped() throws {
        let harness = StreamHarness(savedMutes: savedMutes)
        let reader = TestStreamReader()
        let connection = harness.connect(reader: reader)
        defer { connection.invalidate() }
        reader.holdReplies()
        XCTAssertEqual(connection.send(filteredStream(["ES_EVENT_TYPE_NOTIFY_EXIT", "ES_EVENT_TYPE_NOTIFY_CLOSE"]))?
                        .stream?.fieldFilters, ["ES_EVENT_TYPE_NOTIFY_CLOSE.modified"])
        let factory = try XCTUnwrap(harness.factories.first)
        let limits = EventBatcher.Limits.commandLine
        let inFlight = UInt64(limits.maxBatchesInFlight * limits.batchSize)
        deliverExits(1...inFlight, to: factory)
        XCTAssertTrue(waitUntil { reader.heldCount == limits.maxBatchesInFlight })
        /// One more than fits pauses capture.
        deliverExits((inFlight + 1)...(inFlight + UInt64(limits.memoryLimit) + 1), to: factory)
        XCTAssertEqual(connection.send(StreamRequest(.hello).encoded())?.status, .ok)
        deliverCloses(Array(repeating: false, count: 1_000) + Array(repeating: true, count: 5), to: factory)
        
        reader.releaseReplies()
        XCTAssertTrue(waitUntil {
            reader.releaseReplies()
            return reader.events.count >= limits.memoryLimit + Int(inFlight)
        })
        let summary = try XCTUnwrap(connection.send(StreamRequest(.stop).encoded())?.summary)
        XCTAssertEqual(summary.pauses, 1)
        XCTAssertEqual(summary.skippedWhilePaused, 5)
        XCTAssertEqual(summary.fieldFiltered, ["ES_EVENT_TYPE_NOTIFY_CLOSE": 1_000])
    }
}
