//
//  CommandLineStreamFlowTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - macmonitor stream of network flows, end to end
/// Runs `macmonitor stream new_flow flow_closed` end to end in one process, against a real ``StreamService`` whose
/// capture sessions read flows from a client on a fake socket: the pipeline's own flows are left out, the closing
/// line counts what the kernel couldn't report, a stream of flows alone that can't read them fails, and a stream of
/// all that can't read them, or whose Security Extension doesn't know them yet, streams the rest.
final class CommandLineStreamFlowTests: XCTestCase {
    private var savedMutes = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))
    private let flows = FlowClientHarness()
    /// A scope that suppresses nothing these flows hold.
    private let nobody = PipelineScope(ancestry: [PipelineAncestor(pid: .max, groupID: 0, path: "/x/macmonitor")],
                                       includeSelf: false)

    override func setUpWithError() throws {
        try super.setUpWithError()
        savedMutes = SavedMuteSet(testing: try makeMuteStore())
    }

    /// Start a stream of both flow events, unless given others.
    ///
    /// - Parameters:
    ///   - flows: The client the Security Extension reads flows from.
    ///   - scope: Which processes are the pipeline's.
    ///   - events: The events to stream.
    /// - Returns: The stream, and the Security Extension's side.
    private func startFlows(from flows: FlowClientHarness, scope: PipelineScope,
                            events: [es_event_type_t] = MacMonitorEvent.allCases.map(\.type))
        -> (run: StreamCommandRun, harness: StreamHarness) {
        let harness = StreamHarness(savedMutes: savedMutes, flows: flows.client)
        let run = StreamCommandRun(harness: harness, formatter: .jsonl([ExportEncoder(model: eventModel)]),
                                   scope: scope)
        var invocation = StreamInvocation()
        invocation.events = events
        run.start(invocation)
        addTeardownBlock { withExtendedLifetime(harness) {} }
        return (run, harness)
    }

    /// Start a stream of both flow events, and wait until it has started.
    ///
    /// - Parameters:
    ///   - flows: The client the Security Extension reads flows from.
    ///   - scope: Which processes are the pipeline's.
    /// - Returns: The stream.
    private func streamFlows(from flows: FlowClientHarness, scope: PipelineScope) -> StreamCommandRun {
        let run = startFlows(from: flows, scope: scope).run
        XCTAssertTrue(waitUntil { !run.diagnostics.all.isEmpty }, "The stream never started.")
        return run
    }

    /// Stop a stream and wait for its outcome.
    ///
    /// - Parameter run: The stream.
    private func stop(_ run: StreamCommandRun) {
        run.command.stop()
        XCTAssertTrue(waitUntil { !run.reported.isEmpty })
    }

    /// A stream piped into another program leaves out that program's flows, as it does its other events, so a
    /// stream uploaded by `curl` shows none of its own uploads. Others' flows are written as their records.
    func testThePipelinesOwnFlowsAreLeftOut() throws {
        flows.reads.processes[100]?.groupID = 900
        flows.reads.processes[200] = FakeFlowReads.Process(upid: 6_000, pidversion: 3, groupID: 0)
        let pipeline = PipelineScope(ancestry: [PipelineAncestor(pid: 901, groupID: 900, path: "/x/macmonitor")],
                                     includeSelf: false)
        let run = streamFlows(from: flows, scope: pipeline)
        XCTAssertTrue(flows.feed(flows.flow(pid: 100) + flows.flow(pid: 200)))
        XCTAssertTrue(waitUntil { run.output.lines.count == 2 })
        let records = try run.output.lines.map { try jsonObject(Data($0.utf8)) }
        XCTAssertEqual(records.map { ($0["process"] as? [String: Any])?["pid"] as? Int }, [200, 200])
        XCTAssertEqual(records.compactMap { ($0["event"] as? [String: Any])?.keys.first }, ["new_flow", "flow_closed"])
        XCTAssertTrue(records.allSatisfy { $0["es_event_type"] == nil && $0["global_seq_num"] == nil })
        stop(run)
    }

    /// The closing line counts the sockets the kernel couldn't report, which leave no gap, apart from what was lost.
    func testTheClosingLineCountsWhatTheKernelCouldntReport() {
        let run = streamFlows(from: flows, scope: nobody)
        XCTAssertTrue(flows.feed(flows.flow(lost: 3)))
        XCTAssertTrue(waitUntil { run.output.lines.count == 2 })
        stop(run)
        XCTAssertEqual(run.diagnostics.all.last, """
            macmonitor: wrote 2 events, lost 0 (0 by Endpoint Security, 0 while macmonitor was behind), 3 sockets \
            the kernel couldn't report.
            """)
    }

    /// A stream of flows alone, on a Mac whose network statistics can't be read, fails and says why, since it would
    /// record nothing. It holds no stream's place.
    func testAStreamThatCantReadFlowsFails() {
        let (run, harness) = startFlows(from: FlowClientHarness(refusing: true), scope: nobody)
        XCTAssertTrue(waitUntil { !run.reported.isEmpty })
        guard case .failed(let failure)? = run.reported.first else { return XCTFail("\(run.reported)") }
        XCTAssertEqual(failure.exit, .unavailable)
        XCTAssertEqual(failure.message, "Network flows can't be streamed: Operation not permitted (errno 1)")
        XCTAssertTrue(run.diagnostics.all.isEmpty)
        XCTAssertTrue(waitUntil { harness.service.slots.count == 0 })
        XCTAssertEqual(harness.releases, 1, "Its Endpoint Security clients were let go")
    }

    /// `macmonitor stream all`, on a Mac whose network statistics can't be read, streams every other event and warns
    /// that it can't stream the flows, as a stream naming new_flow beside other events does.
    func testAStreamOfAllThatCantReadFlowsStarts() throws {
        guard case .stream(let all) = try CommandLineParser.parse(["stream", "all"]) else { return XCTFail() }
        let run = startFlows(from: FlowClientHarness(refusing: true), scope: nobody, events: all.events).run
        let warning = "macmonitor: network flows can't be streamed: Operation not permitted (errno 1)"
        XCTAssertTrue(waitUntil { run.diagnostics.all.contains(warning) }, "\(run.diagnostics.all)")
        XCTAssertTrue(run.reported.isEmpty, "It's streaming")
        stop(run)
        guard case .stopped? = run.reported.first else { return XCTFail("\(run.reported)") }
    }

    /// `macmonitor stream all` before Mac Monitor has updated its Security Extension: 3.2.0 refuses a stream naming
    /// the flows, so the stream is asked for again without them, and warns. A stream of the flows alone fails with
    /// the refusal, as asking again without them would stream the defaults.
    func testAStreamOfAllOnAnOlderSecurityExtensionStarts() throws {
        let harness = StreamHarness(savedMutes: savedMutes, flows: flows.client)
        let legacy = LegacyStreamHarness(relayingTo: harness, as: .v3_2)
        let start = { [nobody] (events: [es_event_type_t]) in
            let run = StreamCommandRun(harness: harness, endpoint: legacy.endpoint,
                                       formatter: .jsonl([ExportEncoder(model: eventModel)]), scope: nobody,
                                       toolVersion: "3.3.0 (1)")
            var invocation = StreamInvocation()
            invocation.events = events
            run.start(invocation)
            return run
        }
        guard case .stream(let all) = try CommandLineParser.parse(["stream", "all"]) else { return XCTFail() }
        let run = start(all.events)
        let warning = "macmonitor: network flows can't be streamed: this Security Extension doesn't know them"
        XCTAssertTrue(waitUntil { run.diagnostics.all.contains(warning) }, "\(run.diagnostics.all)")
        let banner = "macmonitor: streaming \(supportedEvents.count) events"
        XCTAssertTrue(run.diagnostics.all.contains { $0.hasPrefix(banner) }, "The rest: \(run.diagnostics.all)")
        XCTAssertTrue(run.reported.isEmpty, "It's streaming")
        stop(run)
        guard case .stopped? = run.reported.first else { return XCTFail("\(run.reported)") }
        let flowsAlone = start(MacMonitorEvent.allCases.map(\.type))
        XCTAssertTrue(waitUntil { !flowsAlone.reported.isEmpty })
        guard case .failed(let failure)? = flowsAlone.reported.first else { return XCTFail("\(flowsAlone.reported)") }
        XCTAssertEqual(failure.message, """
            The Security Extension refused the request. new_flow isn't an event macmonitor can stream on this Mac.
            """)
        withExtendedLifetime(legacy) {}
    }
}
