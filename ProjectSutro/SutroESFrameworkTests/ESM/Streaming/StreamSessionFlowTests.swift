//
//  StreamSessionFlowTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Streams of network flows
/// Pins `macmonitor stream new_flow flow_closed` on the Security Extension's side over a real NSXPC connection: a
/// stream records the flows it names, keeps URL paths unless asked not to, says why it can't read flows or fails
/// without them, counts what it lost of them apart from Endpoint Security's, and a stream stopped while another starts
/// leaves the socket open.
final class StreamSessionFlowTests: XCTestCase {
    private var savedMutes = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))
    private let flows = FlowClientHarness()

    override func setUpWithError() throws {
        try super.setUpWithError()
        savedMutes = SavedMuteSet(testing: try makeMuteStore())
    }

    /// A stream request without the saved mutes.
    ///
    /// - Parameters:
    ///   - events: Event names.
    ///   - urlPaths: Keep URL paths?
    /// - Returns: The request's JSON.
    private func stream(_ events: [String] = ["new_flow", "flow_closed"], urlPaths: Bool = true) -> Data {
        StreamRequest(.stream, options: StreamOptions(events: events, appliesSavedMutes: false,
                                                      recordsURLPaths: urlPaths)).encoded()
    }

    /// The flows a reader received, as `Message`s.
    ///
    /// - Parameter reader: The reader.
    /// - Returns: The flows, in order.
    private func flows(in reader: TestStreamReader) -> [Message] {
        reader.events.compactMap { try? JSONDecoder().decode(Message.self, from: Data($0.utf8)) }
            .filter(\.event.isNetworkFlow)
    }

    /// A stream subscribes to the flow events it names and delivers their flows, whose URLs keep no user, password,
    /// query or fragment. Its summary counts what the client couldn't report.
    func testAStreamRecordsFlows() throws {
        let harness = StreamHarness(savedMutes: savedMutes, flows: flows.client)
        let reader = TestStreamReader()
        let connection = harness.connect(reader: reader)
        defer { connection.invalidate() }
        let started = try XCTUnwrap(connection.send(stream())?.stream)
        XCTAssertEqual(started.events, ["new_flow", "flow_closed"])
        XCTAssertNil(started.networkProblem)
        XCTAssertTrue(flows.play())
        XCTAssertTrue(waitUntil { self.flows(in: reader).count == 2 })
        XCTAssertEqual(flows(in: reader).first?.event.networkFlow?.url, FlowClientHarness.url)
        XCTAssertFalse(reader.events.contains { ["pw@", "token=", "#top"].contains(where: $0.contains) })
        let summary = try XCTUnwrap(connection.send(StreamRequest(.stop).encoded())?.summary)
        XCTAssertEqual(summary.delivered, 2)
        XCTAssertEqual(summary.networkSocketsLost, 0)
        XCTAssertEqual(summary.networkFlowsOverBudget, 0)
        XCTAssertTrue(waitUntil { self.flows.socket == nil }, "A stopped stream closes the socket")
    }

    /// `--no-url-paths` ends each flow's URL at its host.
    func testWithoutURLPaths() throws {
        let harness = StreamHarness(savedMutes: savedMutes, flows: flows.client)
        let reader = TestStreamReader()
        let connection = harness.connect(reader: reader)
        defer { connection.invalidate() }
        XCTAssertEqual(connection.send(stream(urlPaths: false))?.status, .ok)
        XCTAssertTrue(flows.play())
        XCTAssertTrue(waitUntil { self.flows(in: reader).count == 2 })
        let urls = flows(in: reader).map { $0.event.networkFlow?.url }
        XCTAssertEqual(urls, ["https://en.wikipedia.org", "https://en.wikipedia.org"])
    }

    /// A stream of flows alone that can't read them fails, since it would record nothing, and gives its place back.
    /// One with other events streams those, without the flow events, and says why. A stream of Endpoint Security
    /// events alone says nothing of flows.
    func testAStreamWithoutFlowsSaysWhy() throws {
        let harness = StreamHarness(savedMutes: savedMutes, flows: FlowClientHarness(refusing: true).client)
        let alone = harness.connect(reader: TestStreamReader())
        defer { alone.invalidate() }
        let refused = try XCTUnwrap(alone.send(stream()))
        XCTAssertEqual(refused.status, .failed)
        XCTAssertEqual(refused.problem, "Network flows can't be streamed: Operation not permitted (errno 1)")
        XCTAssertNil(refused.stream)
        XCTAssertEqual(harness.service.slots.count, 0)
        let connection = harness.connect(reader: TestStreamReader())
        defer { connection.invalidate() }
        let started = try XCTUnwrap(connection.send(stream(["ES_EVENT_TYPE_NOTIFY_EXIT", "new_flow"])))
        XCTAssertEqual(started.status, .ok)
        XCTAssertEqual(started.stream?.events, ["ES_EVENT_TYPE_NOTIFY_EXIT"])
        XCTAssertEqual(started.stream?.networkProblem, "Operation not permitted (errno 1)")
        let summary = try XCTUnwrap(connection.send(StreamRequest(.stop).encoded())?.summary)
        XCTAssertNil(summary.networkSocketsLost, "It recorded no flows")
        let plain = harness.connect(reader: TestStreamReader())
        defer { plain.invalidate() }
        XCTAssertNil(try XCTUnwrap(plain.send(stream(["ES_EVENT_TYPE_NOTIFY_EXIT"]))?.stream).networkProblem)
    }

    /// Flows that arrive while a stream is paused for its reader are skipped and counted as skipped while paused.
    /// Sockets the kernel couldn't report are counted apart, never as Endpoint Security's drops.
    func testAPausedStreamCountsItsFlows() throws {
        let harness = StreamHarness(savedMutes: savedMutes, flows: flows.client)
        let reader = TestStreamReader()
        let connection = harness.connect(reader: reader)
        defer { connection.invalidate() }
        reader.holdReplies()
        XCTAssertEqual(connection.send(stream(["ES_EVENT_TYPE_NOTIFY_EXIT", "new_flow", "flow_closed"]))?.status, .ok)
        let process = try XCTUnwrap(harness.factories.first).client(.process)
        let limits = EventBatcher.Limits.commandLine
        let inFlight = UInt64(limits.maxBatchesInFlight * limits.batchSize)
        (1...inFlight).forEach { process.deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: $0)) }
        XCTAssertTrue(waitUntil { reader.heldCount == limits.maxBatchesInFlight })
        /// One more than fits pauses capture.
        let overflow = inFlight + UInt64(limits.memoryLimit) + 1
        ((inFlight + 1)...overflow).forEach { process.deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: $0)) }
        /// Answered on the stream's queue after every event before it, so capture is paused by then.
        XCTAssertEqual(connection.send(StreamRequest(.hello).encoded())?.status, .ok)
        XCTAssertTrue(flows.feed(flows.flow() + flows.flow(lost: 2)))
        XCTAssertTrue(waitUntil {
            reader.releaseReplies()
            return reader.events.count >= limits.memoryLimit + Int(inFlight)
        })
        let summary = try XCTUnwrap(connection.send(StreamRequest(.stop).encoded())?.summary)
        XCTAssertEqual(summary.pauses, 1)
        XCTAssertEqual(summary.skippedWhilePaused, 4, "Two flows' openings and closes")
        XCTAssertEqual(summary.networkSocketsLost, 2)
        XCTAssertEqual(summary.droppedByEndpointSecurity, 0)
        XCTAssertTrue(flows(in: reader).isEmpty)
    }

    /// A stream that starts while another is stopping leaves the socket open for the one that started, which gets
    /// its flows. The first stream's stop waits in its drain until the second has started.
    func testAStreamStoppedAsAnotherStarts() throws {
        let harness = StreamHarness(savedMutes: savedMutes, holdsSyncs: true, flows: flows.client)
        let (firstReader, secondReader) = (TestStreamReader(), TestStreamReader())
        let first = harness.connect(reader: firstReader), second = harness.connect(reader: secondReader)
        defer { [first, second].forEach { $0.invalidate() } }
        XCTAssertEqual(first.send(stream())?.status, .ok)
        let stopped = Recorded<StreamReply?>()
        first.sendAsync(StreamRequest(.stop).encoded(), completion: stopped.append)
        let draining = try XCTUnwrap(harness.factories.first)
        XCTAssertTrue(waitUntil { draining.clients.contains { !$0.calls(.sync).isEmpty } })
        XCTAssertEqual(second.send(stream())?.status, .ok)
        draining.clients.forEach { $0.releaseSyncs() }
        XCTAssertTrue(waitUntil { stopped.all.count == 1 && harness.service.slots.count == 1 })
        XCTAssertEqual(flows.sockets.all.count, 1, "The socket stayed open")
        XCTAssertNotNil(flows.socket)
        XCTAssertTrue(flows.play())
        XCTAssertTrue(waitUntil { self.flows(in: secondReader).count == 2 })
    }

    /// A status request says how the network statistics client is doing.
    func testTheStatusReportsTheClient() throws {
        let harness = StreamHarness(savedMutes: savedMutes, flows: flows.client)
        let connection = harness.connect(reader: TestStreamReader())
        defer { connection.invalidate() }
        XCTAssertEqual(connection.send(StreamRequest(.status).encoded())?.report?.network?.state, .off)
        XCTAssertEqual(connection.send(stream())?.status, .ok)
        let watcher = harness.connect(reader: TestStreamReader())
        defer { watcher.invalidate() }
        let network = try XCTUnwrap(watcher.send(StreamRequest(.status).encoded())?.report?.network)
        XCTAssertEqual(network.state, .on)
        XCTAssertEqual(network.receiveBuffer, 4_194_304)
    }
}
