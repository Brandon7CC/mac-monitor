//
//  CommandLineStreamTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - macmonitor stream, end to end
/// Runs `macmonitor stream` end to end in one process: ``StreamCommand`` and ``StreamClient`` over a real NSXPC
/// connection to a real ``StreamService``, whose capture session builds real events (``MessageSerializer``) from
/// messages its fake Endpoint Security clients deliver. Only Endpoint Security, root, and code signing are left out.
final class CommandLineStreamTests: XCTestCase {
    private var savedMutes = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))
    private let utc = TextEventFormatter(timeZone: TimeZone(identifier: "UTC")!)
    /// A scope that suppresses nothing these events hold.
    private let nobody = PipelineScope(ancestry: [PipelineAncestor(pid: .max, groupID: 0, path: "/x/macmonitor")],
                                       includeSelf: false)
    
    /// A saved set in a fresh directory.
    ///
    /// - Throws: If the directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        savedMutes = SavedMuteSet(testing: try makeMuteStore())
    }
    
    /// The in-process Security Extension, building real events.
    ///
    /// - Parameters:
    ///   - capacity: The most streams at once.
    ///   - admits: Treat every caller as root?
    ///   - holdsSyncs: Every stream's clients hold their syncs from the start, so each stop's drain waits for the test.
    /// - Returns: The harness.
    private func makeHarness(capacity: Int = 3, admits: Bool = true, holdsSyncs: Bool = false) -> StreamHarness {
        StreamHarness(savedMutes: savedMutes, capacity: capacity, admits: admits, serializer: MessageSerializer(),
                      holdsSyncs: holdsSyncs)
    }
    
    /// Wait until the stream has started (its answer was handled, so its capture session is recording), then hand
    /// its process client exit messages.
    ///
    /// - Parameters:
    ///   - sequences: Their `seq_num` and `global_seq_num`.
    ///   - harness: The harness.
    ///   - run: The stream.
    /// - Throws: An `XCTest` failure if no stream started.
    private func deliverExits(_ sequences: [UInt64], in harness: StreamHarness, to run: StreamCommandRun) throws {
        XCTAssertTrue(waitUntil { !run.diagnostics.all.isEmpty }, "The stream never started.")
        let client = try XCTUnwrap(harness.factories.last?.clients.first)
        sequences.forEach { client.deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, seq: $0, global: $0)) }
    }
    
    /// Stop a stream and wait for its outcome.
    ///
    /// - Parameter run: The stream.
    /// - Returns: The outcome.
    /// - Throws: An `XCTest` failure if there's none.
    private func stop(_ run: StreamCommandRun) throws -> StreamCommand.Outcome {
        run.command.stop()
        XCTAssertTrue(waitUntil { !run.reported.isEmpty })
        return try XCTUnwrap(run.reported.first)
    }
    
    /// Text: one line per event as it arrives, then a stop that ends with the summary, a banner before it.
    func testATextStream() throws {
        let harness = makeHarness()
        let run = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody)
        var invocation = StreamInvocation()
        invocation.events = [ES_EVENT_TYPE_NOTIFY_EXIT]
        run.start(invocation)
        try deliverExits([1, 2, 3], in: harness, to: run)
        XCTAssertTrue(waitUntil { run.output.lines.count == 3 })
        let line = "00:01:54.394  exit          true[123]  root  true"
        XCTAssertEqual(run.output.lines, Array(repeating: line, count: 3))
        guard case .stopped(let summary?) = try stop(run) else { return XCTFail("\(run.reported)") }
        XCTAssertEqual(summary.delivered, 3)
        XCTAssertEqual(run.diagnostics.all, [
            "macmonitor: streaming 1 event with \(MuteList.testDefault.count) saved mutes (--no-mutes shows "
                + "everything). Press Ctrl-C to stop.",
            "macmonitor: wrote 3 events, lost 0 (0 by Endpoint Security, 0 while macmonitor was behind)."
        ])
        XCTAssertTrue(waitUntil { harness.service.slots.count == 0 })
        XCTAssertEqual(run.reported.count, 1)
    }
    
    /// JSONL: one export record per event, in order, without the saved mutes when asked.
    func testAJSONLStreamWithoutMutes() throws {
        let harness = makeHarness()
        let run = StreamCommandRun(harness: harness, formatter: .jsonl([ExportEncoder(model: eventModel)]),
                                   scope: nobody)
        var invocation = StreamInvocation()
        invocation.events = [ES_EVENT_TYPE_NOTIFY_EXIT]
        invocation.appliesSavedMutes = false
        run.start(invocation)
        try deliverExits([1, 2], in: harness, to: run)
        XCTAssertTrue(waitUntil { run.output.lines.count == 2 })
        let records = try run.output.lines.map { line in try jsonObject(Data(line.utf8)) }
        XCTAssertEqual(records.map { $0["global_seq_num"] as? Int }, [1, 2])
        XCTAssertEqual(records.map { $0["es_event_type"] as? String },
                       Array(repeating: "ES_EVENT_TYPE_NOTIFY_EXIT", count: 2))
        XCTAssertTrue(run.diagnostics.all.first?.contains("without the saved mutes") == true)
        XCTAssertTrue(harness.factories[0].clients.allSatisfy { $0.calls(.setPathMute).isEmpty })
        _ = try stop(run)
    }
    
    /// `--count` writes that many events, then stops the stream itself: a stop, not a failure, so `macmonitor`
    /// exits 0. The banner says how it ends.
    func testACountStopsTheStream() throws {
        let harness = makeHarness()
        let run = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody, limit: 2)
        var invocation = StreamInvocation()
        invocation.events = [ES_EVENT_TYPE_NOTIFY_EXIT]
        invocation.limit = 2
        run.start(invocation)
        try deliverExits([1, 2, 3], in: harness, to: run)
        XCTAssertTrue(waitUntil { !run.reported.isEmpty })
        guard case .stopped = run.reported.first else { return XCTFail("\(run.reported)") }
        XCTAssertEqual(run.output.lines.count, 2)
        XCTAssertEqual(run.diagnostics.all.first?.hasSuffix(" Stops after 2 events, or press Ctrl-C."), true)
        XCTAssertEqual(run.diagnostics.all.last?.hasPrefix("macmonitor: wrote 2 events, lost 0"), true)
        run.command.stop()
        XCTAssertTrue(waitUntil { harness.service.slots.count == 0 })
        XCTAssertEqual(run.reported.count, 1)
    }
    
    /// A stream that stops itself at its `--count` waits for the stop's answer however long the drain takes. The old
    /// 2 second limit ended such a stream with exit 69 and lost what was still queued. Both streams here have a 50 ms
    /// stop limit, and the second one's signal stop, sent after the first stream's own stop, gives up first.
    func testASelfStopWaitsForItsAnswer() throws {
        /// Each drain waits on Endpoint Security's sync, so each answer waits too.
        let harness = makeHarness(holdsSyncs: true)
        let counted = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody, limit: 1,
                                       stopTimeout: .milliseconds(50))
        var invocation = StreamInvocation()
        invocation.events = [ES_EVENT_TYPE_NOTIFY_EXIT]
        invocation.limit = 1
        counted.start(invocation)
        try deliverExits([1], in: harness, to: counted)
        XCTAssertTrue(waitUntil { counted.output.lines.count == 1 })
        let clients = try XCTUnwrap(harness.factories.last?.clients)
        XCTAssertTrue(waitUntil { clients.allSatisfy { !$0.calls(.sync).isEmpty } }, "The stream never stopped itself.")
        
        let signalled = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody,
                                         stopTimeout: .milliseconds(50))
        signalled.start()
        XCTAssertTrue(waitUntil { !signalled.diagnostics.all.isEmpty }, "The second stream never started.")
        signalled.command.stop()
        XCTAssertTrue(waitUntil { !signalled.reported.isEmpty })
        XCTAssertEqual(signalled.reported, [.failed(.noAnswer)])
        XCTAssertEqual(counted.reported, [])
        
        clients.forEach { $0.releaseSyncs() }
        XCTAssertTrue(waitUntil { !counted.reported.isEmpty })
        guard case .stopped(let summary?) = counted.reported.first else { return XCTFail("\(counted.reported)") }
        XCTAssertEqual(summary.delivered, 1)
    }
        
    /// `--for` stops the stream itself once the time is up, with every event captured before then written. A
    /// fraction of a second works, and the clients hold the stop's drain until the test has seen both exits written.
    func testATimeStopsTheStream() throws {
        let harness = makeHarness(holdsSyncs: true)
        let run = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody)
        var invocation = StreamInvocation()
        invocation.events = [ES_EVENT_TYPE_NOTIFY_EXIT]
        invocation.duration = 0.05
        run.start(invocation)
        try deliverExits([1, 2], in: harness, to: run)
        XCTAssertTrue(waitUntil { run.output.lines.count == 2 })
        /// Only the time stops this stream, so a sync means its stop is draining.
        let clients = try XCTUnwrap(harness.factories.last?.clients)
        XCTAssertTrue(waitUntil { clients.allSatisfy { !$0.calls(.sync).isEmpty } }, "The time never stopped it.")
        clients.forEach { $0.releaseSyncs() }
        XCTAssertTrue(waitUntil { !run.reported.isEmpty })
        guard case .stopped(let summary?) = run.reported.first else { return XCTFail("\(run.reported)") }
        XCTAssertEqual(summary.delivered, 2)
        XCTAssertEqual(run.output.lines.count, 2)
        XCTAssertEqual(run.diagnostics.all.first?.hasSuffix(" Stops after 50 milliseconds, or press Ctrl-C."), true,
                       "\(run.diagnostics.all)")
        XCTAssertEqual(StreamCommand.describe(5_400), "1 hour, 30 minutes")
        XCTAssertEqual(StreamCommand.describe(30), "30 seconds")
    }
    
    /// The closing line says how many events the filter left out.
    func testTheSummarySaysWhatWasFiltered() throws {
        let harness = makeHarness()
        var filter = StreamFilter()
        filter.pids = [999]
        let run = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody, filter: filter)
        run.start()
        try deliverExits([1, 2], in: harness, to: run)
        _ = try stop(run)
        XCTAssertEqual(run.output.data, Data())
        XCTAssertEqual(run.diagnostics.all.last,
                       "macmonitor: wrote 0 events (2 filtered out), lost 0 (0 by Endpoint Security, 0 while "
                       + "macmonitor was behind).")
    }
    
    /// A stop writes everything captured before it, including messages still queued in Endpoint Security.
    func testAStopWritesEverythingCapturedBeforeIt() throws {
        let harness = makeHarness()
        let run = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody)
        run.start()
        try deliverExits([1, 2], in: harness, to: run)
        let clients = harness.factories[0].clients
        clients.forEach { $0.holdSyncs() }
        run.command.stop()
        XCTAssertTrue(waitUntil { clients.allSatisfy { !$0.calls(.sync).isEmpty } })
        try deliverExits([3], in: harness, to: run)
        clients.forEach { $0.releaseSyncs() }
        XCTAssertTrue(waitUntil { !run.reported.isEmpty })
        XCTAssertEqual(run.output.lines.count, 3)
        guard case .stopped(let summary?) = run.reported.first else { return XCTFail("\(run.reported)") }
        XCTAssertEqual(summary.delivered, 3)
    }
    
    /// Lost events are reported as they're seen, by type, and the summary says Endpoint Security lost them.
    func testLostEventsAreReported() throws {
        let harness = makeHarness()
        let run = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody)
        run.start()
        try deliverExits([1, 2, 5], in: harness, to: run)
        XCTAssertTrue(waitUntil { run.output.lines.count == 3 })
        _ = try stop(run)
        XCTAssertEqual(Array(run.diagnostics.all.dropFirst()), [
            "macmonitor: lost 2 events (exit 2)",
            "macmonitor: wrote 3 events, lost 2 (2 by Endpoint Security, 0 while macmonitor was behind)."
        ])
    }
    
    /// The pipeline's own events are counted but not written.
    func testThePipelinesOwnEventsAreLeftOut() throws {
        let harness = makeHarness()
        let ownScope = PipelineScope(ancestry: [PipelineAncestor(pid: 123, groupID: 0, path: "/x/macmonitor")],
                                     includeSelf: false)
        let run = StreamCommandRun(harness: harness, formatter: .text(utc), scope: ownScope)
        run.start()
        try deliverExits([1, 2], in: harness, to: run)
        guard case .stopped(let summary?) = try stop(run) else { return XCTFail("\(run.reported)") }
        XCTAssertEqual(summary.delivered, 2)
        XCTAssertEqual(run.output.text, "")
    }
    
    /// A reader that closes the pipe ends the stream as a success, and the Security Extension frees the stream.
    func testAClosedPipeIsASuccess() throws {
        let harness = makeHarness()
        let run = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody)
        run.output.fail(with: .closed)
        run.start()
        try deliverExits([1], in: harness, to: run)
        XCTAssertTrue(waitUntil { !run.reported.isEmpty })
        XCTAssertEqual(run.reported, [.outputClosed])
        XCTAssertTrue(waitUntil { harness.service.slots.count == 0 })
        XCTAssertTrue(harness.factories[0].clients.allSatisfy { $0.calls(.delete).count == 1 })
    }
    
    /// A failed write ends the stream with exit 74.
    func testAFailedWriteIsAnOutputError() throws {
        let harness = makeHarness()
        let run = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody)
        run.output.fail(with: .failed(ENOSPC))
        run.start()
        try deliverExits([1], in: harness, to: run)
        XCTAssertTrue(waitUntil { !run.reported.isEmpty })
        guard case .failed(let failure) = run.reported.first else { return XCTFail("\(run.reported)") }
        XCTAssertEqual(failure.exit, .ioError)
    }
    
    /// Refusals end the stream with their exit status: no slot (75), not root (77).
    func testRefusalsEndTheStream() {
        for (harness, exit) in [(makeHarness(capacity: 0), CommandLineExit.temporaryFailure),
                                (makeHarness(admits: false), .noPermission)] {
            let run = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody)
            run.start()
            XCTAssertTrue(waitUntil { !run.reported.isEmpty })
            guard case .failed(let failure) = run.reported.first else { return XCTFail("\(run.reported)") }
            XCTAssertEqual(failure.exit, exit)
        }
    }
    
    /// The default rule admits only root. It's asked on the thread delivering the request, with the caller's real
    /// connection, and its refusal says how to run the same command line with sudo.
    func testTheDefaultRuleAdmitsOnlyRoot() throws {
        XCTAssertEqual(StreamService.rootOnly(nil), .refused(CommandLineAccess.needsRoot))
        let asked = Recorded<uid_t?>()
        let recording = StreamHarness(savedMutes: savedMutes, admitting: { connection in
            asked.append(connection?.effectiveUserIdentifier)
            return StreamService.rootOnly(connection)
        })
        let run = StreamCommandRun(harness: recording, formatter: .text(utc), scope: nobody)
        run.start()
        XCTAssertTrue(waitUntil { !run.reported.isEmpty || !recording.factories.isEmpty })
        XCTAssertEqual(asked.all.first, geteuid())
        guard geteuid() != 0 else { return }
        guard case .failed(let failure) = run.reported.first else { return XCTFail("\(run.reported)") }
        XCTAssertEqual(failure.exit, .noPermission)
        XCTAssertEqual(failure.message, CommandLineAccess.needsRoot)
        XCTAssertTrue(failure.suggestingSudo(arguments: ["stream"], isRoot: false).message
                        .hasSuffix("Run it with sudo: sudo macmonitor stream"))
        XCTAssertTrue(recording.factories.isEmpty, "No capture for a caller that isn't root")
    }
    
    /// `macmonitor` pins the Security Extension's signature. NSXPC checks it on what comes back, so a service that
    /// isn't signed as Mac Monitor's Security Extension, such as this test process, still gets the request, but
    /// nothing it sends is believed. A batch it sends ahead of its answer, while the stream still waits for one, is
    /// never written, and ends the stream. Its answer fails the stream too. Either way `macmonitor` exits 69 and says
    /// the signature is wrong. Registering the Security Extension's service name takes root.
    func testMacmonitorBelievesNothingFromAnUnsignedSecurityExtension() throws {
        let event = try wire(try XCTUnwrap(fixtureMessages("eslogger-exit.jsonl").first))
        let delivered = expectation(description: "macmonitor answered or refused the batch")
        delivered.assertForOverFulfill = false
        /// Asked once, for the stream request, before it's answered. A batch sent here arrives ahead of the answer.
        let pushing = StreamHarness(savedMutes: savedMutes, admitting: { connection in
            let proxy = connection?.remoteObjectProxyWithErrorHandler { _ in delivered.fulfill() }
            (proxy as? StreamReaderProtocol)?.receive(events: [event]) { delivered.fulfill() }
            return .everything
        }, serializer: MessageSerializer())
        let pushed = StreamCommandRun(harness: pushing, formatter: .text(utc), scope: nobody,
                                      requirement: SensorXPC.sensorRequirement)
        pushed.start()
        wait(for: [delivered], timeout: 5)
        XCTAssertEqual(pushed.output.lines, [])
        XCTAssertTrue(waitUntil { !pushed.reported.isEmpty })
        XCTAssertEqual(pushed.reported, [.failed(.signatureMismatch)])
        
        let harness = makeHarness()
        let run = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody,
                                   requirement: SensorXPC.sensorRequirement)
        run.start()
        XCTAssertTrue(waitUntil { !run.reported.isEmpty })
        XCTAssertEqual(run.reported, [.failed(.signatureMismatch)])
        XCTAssertEqual(CommandLineFailure.signatureMismatch.exit, .unavailable)
        XCTAssertTrue(CommandLineFailure.signatureMismatch.message.contains("signature"))
        /// Its capture started before it answered.
        XCTAssertEqual(harness.factories.count, 1, "The request never reached the Security Extension.")
    }
    
    /// A Security Extension that goes away mid-stream ends it with exit 69, once.
    func testTheSecurityExtensionGoingAwayEndsTheStream() throws {
        let harness = makeHarness()
        let run = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody)
        run.start()
        try deliverExits([1], in: harness, to: run)
        XCTAssertTrue(waitUntil { run.output.lines.count == 1 })
        harness.dropConnections()
        XCTAssertTrue(waitUntil { !run.reported.isEmpty })
        XCTAssertEqual(run.reported, [.failed(.stopped)])
        usleep(100_000)
        XCTAssertEqual(run.reported.count, 1)
    }
    
    /// A Security Extension of another version gets a warning, and the stream goes on.
    func testAVersionMismatchIsAWarning() throws {
        let harness = makeHarness()
        let run = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody, toolVersion: "2.2.1 (2)")
        run.start()
        try deliverExits([1], in: harness, to: run)
        XCTAssertTrue(waitUntil { run.output.lines.count == 1 })
        XCTAssertEqual(run.diagnostics.all.first, """
            macmonitor: macmonitor is 2.2.1 (2) but the Security Extension is 3.0.0 (1). Open Mac Monitor to finish \
            updating.
            """)
        _ = try stop(run)
    }
    
    /// A change to the saved mute set while a stream follows it is said on standard error, terminal or not, with who
    /// made it. A `--no-mutes` stream says nothing.
    func testSavedMuteChangesAreSaid() throws {
        let harness = makeHarness()
        let following = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody, isChatty: false)
        let bare = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody, isChatty: false)
        following.start()
        /// Each stream's capture starts once it follows the saved set.
        XCTAssertTrue(waitUntil { harness.factories.count == 1 })
        var noMutes = StreamInvocation()
        noMutes.appliesSavedMutes = false
        bare.start(noMutes)
        XCTAssertTrue(waitUntil { harness.factories.count == 2 })
        
        let changer = harness.connect(reader: TestStreamReader())
        defer { changer.invalidate() }
        let entry = MuteFile.Entry(path: "/usr/bin/yes", type: "ES_MUTE_PATH_TYPE_LITERAL")
        XCTAssertEqual(changer.sendMutes(MuteRequest(.add, [entry]))?.status, .ok)
        XCTAssertTrue(waitUntil { !following.diagnostics.all.isEmpty })
        XCTAssertEqual(following.diagnostics.all, ["""
            macmonitor: macmonitor (pid \(getpid())) changed the saved mute set: 1 added, 0 removed, 0 changed, \
            \(MuteList.testDefault.count + 1) mutes now. This stream applies it; --no-mutes shows everything.
            """])
        _ = try stop(following)
        _ = try stop(bare)
        XCTAssertEqual(bare.diagnostics.all, [])
        XCTAssertEqual(StreamCommand.describe(nil),
                       "The saved mute set changed. This stream applies it; --no-mutes shows everything.")
    }
}
