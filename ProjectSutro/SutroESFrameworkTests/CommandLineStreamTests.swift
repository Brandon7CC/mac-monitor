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
    /// - Returns: The harness.
    private func makeHarness(capacity: Int = 3, admits: Bool = true) -> StreamHarness {
        StreamHarness(savedMutes: savedMutes, capacity: capacity, admits: admits, serializer: MessageSerializer())
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
    ///
    /// - Throws: An `XCTest` failure.
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
    ///
    /// - Throws: An `XCTest` failure, or the error parsing a record.
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
        let records = try run.output.lines.map { line in
            try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
        }
        XCTAssertEqual(records.map { $0["global_seq_num"] as? Int }, [1, 2])
        XCTAssertEqual(records.map { $0["es_event_type"] as? String },
                       Array(repeating: "ES_EVENT_TYPE_NOTIFY_EXIT", count: 2))
        XCTAssertTrue(run.diagnostics.all.first?.contains("without the saved mutes") == true)
        XCTAssertTrue(harness.factories[0].clients.allSatisfy { $0.calls(.setPathMute).isEmpty })
        _ = try stop(run)
    }
    
    /// A stop writes everything captured before it, including messages still queued in Endpoint Security.
    ///
    /// - Throws: An `XCTest` failure.
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
    ///
    /// - Throws: An `XCTest` failure.
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
    ///
    /// - Throws: An `XCTest` failure.
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
    ///
    /// - Throws: An `XCTest` failure.
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
    ///
    /// - Throws: An `XCTest` failure.
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
    
    /// A Security Extension that goes away mid-stream ends it with exit 69, once.
    ///
    /// - Throws: An `XCTest` failure.
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
    ///
    /// - Throws: An `XCTest` failure.
    func testAVersionMismatchIsAWarning() throws {
        let harness = makeHarness()
        let run = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody, toolVersion: "2.2.1 (2)")
        run.start()
        try deliverExits([1], in: harness, to: run)
        XCTAssertTrue(waitUntil { run.output.lines.count == 1 })
        XCTAssertEqual(run.diagnostics.all.first, """
            macmonitor: macmonitor is 2.2.1 (2) but the Security Extension is 2.2.0 (1). Open Mac Monitor to finish \
            updating.
            """)
        _ = try stop(run)
    }
    
    /// A change to the saved mute set while a stream follows it is said on standard error, terminal or not, with who
    /// made it; a `--no-mutes` stream says nothing.
    ///
    /// - Throws: An `XCTest` failure.
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
