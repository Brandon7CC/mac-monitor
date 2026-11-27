//
//  NetworkStatisticsClientTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - The client
/// Pins the client around its table: what it asks a new socket for, when the socket opens and closes, how it reads,
/// polls and checks for losses, how it reopens on macOS 13 and 14, and what delivery completes.
final class NetworkStatisticsClientTests: XCTestCase {
    /// The seconds the client's clock is ahead of the start.
    let later = OSAllocatedUnfairLock(initialState: 0.0)
    /// The sockets made, in order.
    let sockets = Recorded<FakeFlowSocket>()
    let consumer = FlowCollector()

    /// A client on fake sockets and a clock the test moves.
    ///
    /// - Parameters:
    ///   - darwin: The Darwin version.
    ///   - reads: The process reads.
    ///   - lineage: The lineage table.
    ///   - failures: The kernel's add failures.
    ///   - refusing: Refuse to open a socket?
    ///   - failing: The errno each socket answers a request with.
    /// - Returns: The client.
    func makeClient(darwin: Int = 27, reads: FakeFlowReads = FakeFlowReads(), lineage: ProcessLineage? = nil,
                            failures: @escaping () -> UInt32? = { nil }, refusing: Bool = false,
                            failing: @escaping ([UInt8]) -> Int32 = { _ in 0 }) -> NetworkStatisticsClient {
        .fake(darwin: darwin, reads: reads, lineage: lineage,
              clock: { [later] in FlowTableHarness.clock(later.withLock { $0 }) }, failures: failures,
              refusing: refusing, failing: failing, sockets: sockets)
    }

    /// Hand datagrams to the client's socket, and wait until they're read and delivered and what's due is done.
    ///
    /// - Parameters:
    ///   - client: The client.
    ///   - datagrams: The datagrams.
    func feed(_ client: NetworkStatisticsClient, _ datagrams: [UInt8]...) {
        feed(client, all: datagrams)
    }

    /// Hand datagrams to the client's socket, and wait until they're read and delivered and what's due is done.
    ///
    /// - Parameters:
    ///   - client: The client.
    ///   - datagrams: The datagrams.
    func feed(_ client: NetworkStatisticsClient, all datagrams: [[UInt8]]) {
        sockets.all.last?.deliver(datagrams)
        let drained = expectation(description: "Drained")
        client.drain { drained.fulfill() }
        wait(for: [drained], timeout: 5)
    }

    /// A new socket is asked first for the updates mode, then for each provider's sources with the domain item, the
    /// userland ones with their NECP parameters, and kernel TCP for its connect update from Darwin 23.
    func testANewSocketAsksForEverySource() throws {
        for darwin in [22, 23, 24, 27] {
            let client = makeClient(darwin: darwin)
            XCTAssertEqual(client.register(consumer).state, .on)
            let sent = try XCTUnwrap(sockets.all.last).sent.all
            XCTAssertEqual(sent.count, 7)
            XCTAssertEqual(sent.first, NStat.getUpdate(0, context: 0x7000_0000_0000_0000) { Array($0) })
            for (request, provider) in zip(sent.dropFirst(), NStat.Provider.allCases) {
                let events: UInt64 = provider == .tcpKernel && darwin >= 23 ? 0x2000 : 0
                let filter = provider.filter(darwin: darwin)
                XCTAssertEqual(request, NStat.addAll(provider.rawValue, filter: filter, events: events,
                                                     context: NStat.Request.add(provider).context) { Array($0) })
            }
            XCTAssertEqual(client.status.state, .on)
            XCTAssertEqual(client.status.receiveBuffer, 4_194_304)
            client.unregister(consumer)
        }
    }

    /// A socket that can't be opened leaves the client unavailable with the reason, and the consumer isn't kept.
    /// The next registration tries again.
    func testAnUnavailableSocketKeepsNoConsumer() {
        let refused = makeClient(refusing: true)
        XCTAssertEqual(refused.register(consumer).state, .unavailable)
        XCTAssertEqual(refused.status.state, .unavailable)
        XCTAssertEqual(refused.status.reason, "Operation not permitted (errno 1)")
        let client = makeClient()
        XCTAssertEqual(client.register(consumer).state, .on)
    }

    /// The last consumer's removal closes the socket and empties the table. A removal and an addition that race
    /// leave the socket open: each decision is made from the consumers as they are when it runs.
    func testTheSocketFollowsItsConsumers() throws {
        let client = makeClient()
        client.register(consumer)
        let first = try XCTUnwrap(sockets.all.first)
        client.unregister(consumer)
        XCTAssertTrue(first.isClosed)
        XCTAssertEqual(client.status, FlowClientStatus())
        client.register(consumer)
        let held = DispatchSemaphore(value: 0), done = DispatchGroup(), other = FlowCollector()
        client.readQueue.async { held.wait() }
        DispatchQueue.global().async(group: done) { client.unregister(self.consumer) }
        DispatchQueue.global().async(group: done) { client.register(other) }
        let changed = waitUntil { client.consumers.withLockUnchecked { $0.count == 1 && $0.first === other } }
        XCTAssertTrue(changed, "Both changed the consumers before either reconciles")
        held.signal()
        XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(sockets.all.count, 2)
        XCTAssertFalse(try XCTUnwrap(sockets.all.last).isClosed)
        XCTAssertEqual(client.status.state, .on)
    }

    /// A consumer is told the counts as it joins and leaves, read in the same step as the decision to open or close
    /// the socket. So a socket it opens has none, and one it joins has what was counted before it.
    func testConsumersLearnTheCountsAsTheyJoinAndLeave() {
        let client = makeClient(), other = FlowCollector(), build = NStatMessageBuilder()
        XCTAssertEqual(client.register(consumer).counts, FlowCounts())
        feed(client, build.added(1, .tcpUserland) + build.added(5, .tcpUserland))
        XCTAssertEqual(client.register(other).counts.lostSources, 3)
        XCTAssertEqual(client.unregister(consumer).lostSources, 3)
        XCTAssertEqual(client.unregister(other).lostSources, 3)
        XCTAssertEqual(client.register(consumer).counts, FlowCounts(), "A socket it opens has none")
    }

    /// Every consumer gets every record, in order. Gaps in source references are counted exactly, and a datagram
    /// too big for the buffer is counted and grows it.
    func testReadingAndDelivery() throws {
        let client = makeClient(), other = FlowCollector(), build = NStatMessageBuilder()
        let descriptor = FlowTableHarness().descriptor()
        client.register(consumer)
        client.register(other)
        feed(client, build.added(1, .tcpUserland) + build.added(2, .tcpUserland) + build.added(6, .tcpUserland),
             build.update(1, .tcpUserland, descriptor), build.update(1, .tcpUserland, descriptor, flags: NStat.closing),
             build.removed(1))
        XCTAssertEqual(consumer.records.all.map(\.kind), [.opened, .closed])
        XCTAssertEqual(other.records.all.map(\.identifier), consumer.records.all.map(\.identifier))
        XCTAssertEqual(client.status.counts.lostSources, 3)
        let filler = Array((0..<3_000).map { _ in build.removed(999) }.joined())
        feed(client, filler, filler + build.added(7, .udpSubflow))
        XCTAssertEqual(client.status.counts.truncated, 1)
        XCTAssertEqual(client.status.openSources, 3, "Sources 2, 6 and 7: the second big datagram was read whole")
    }

    /// A kernel TCP socket is polled until it connects, on Darwin 22 and 27 alike.
    func testAKernelSocketIsPolledUntilItConnects() throws {
        for darwin in [22, 27] {
            let client = makeClient(darwin: darwin), build = NStatMessageBuilder(darwin: darwin)
            var descriptor = FlowTableHarness().descriptor(remote: nil)
            descriptor.state = 0
            client.register(consumer)
            feed(client, build.added(2, .tcpKernel), build.update(2, .tcpKernel, descriptor))
            later.withLock { $0 += 0.15 }
            feed(client)
            let queries = try XCTUnwrap(sockets.all.last).queries
            XCTAssertEqual(queries, [.query(2), .query(2)], "Darwin \(darwin)")
            client.unregister(consumer)
            later.withLock { $0 = 0 }
        }
    }

    /// A provider whose add can't even be answered with an error is off, and status names it with the error.
    func testAProviderWhoseAddCantBeSentIsOff() {
        let client = makeClient(failing: { request in request.count == 56 && request[32] == 5 ? ENOBUFS : 0 })
        XCTAssertEqual(client.register(consumer).state, .on)
        XCTAssertEqual(client.status.providersOff, ["udpUserland": String(cString: strerror(ENOBUFS))])
    }

    /// An update too long for one 2,048-byte message comes whole as the reply to its source's own query. The
    /// client never asks for every source's update at once, which would cut it.
    func testALongUpdateIsTheReplyToItsQuery() throws {
        let client = makeClient(), build = NStatMessageBuilder()
        client.register(consumer)
        feed(client, build.added(1, .tcpUserland))
        let socket = try XCTUnwrap(sockets.all.last)
        XCTAssertEqual(socket.queries, [.query(1)])
        let url = "https://en.wikipedia.org/wiki/" + String(repeating: "how-to-", count: 300)
        feed(client, build.update(1, .tcpUserland, FlowTableHarness().descriptor(),
                                  items: [.domain(""), .parameters([(42, Array(url.utf8))])]))
        XCTAssertEqual(consumer.records.all.first?.url, String(url.prefix(FlowURL.limit)))
        let all = socket.sent.all.filter { $0.count == 24 && $0.withUnsafeBytes { $0.integer(at: 16) } == UInt64.max }
        XCTAssertTrue(all.isEmpty, "No query for every source")
    }

    /// A flow's close names the program its opening did, though the lineage table learned of a newer one for the
    /// pid in between.
    func testAFlowsTwoRecordsNameOneProgram() throws {
        let lineage = ProcessLineage(reader: nil, patience: 0.05)
        let client = makeClient(lineage: lineage), build = NStatMessageBuilder()
        client.register(consumer)
        /// Tell the table pid 300 exec'd a program.
        func exec(_ version: Int32, _ path: String) {
            lineage.exec(ProcessProgram(key: ProcessKey(pid: 300, pidversion: version), path: path),
                         replacing: ProcessKey(pid: 300, pidversion: version - 1),
                         token: RawMessageFixture.auditToken(pid: 300, pidversion: UInt32(version)), at: 0)
            lineage.told(upTo: .max)
        }
        exec(1, "/usr/bin/nscurl")
        var reaped = FlowTableHarness().descriptor()
        (reaped.pid, reaped.upid) = (300, 9)
        feed(client, build.added(1, .tcpUserland), build.update(1, .tcpUserland, reaped))
        exec(2, "/usr/local/bin/nscurl-helper")
        feed(client, build.update(1, .tcpUserland, reaped, flags: NStat.closing), build.removed(1))
        XCTAssertEqual(consumer.records.all.map { $0.process.program?.path }, ["/usr/bin/nscurl", "/usr/bin/nscurl"])
    }

    /// Random datagrams, and built ones with random bytes changed, never stop the client: whatever the kernel
    /// sends, the Security Extension stays up.
    func testRandomDatagramsNeverTrap() {
        let client = makeClient(), build = NStatMessageBuilder(), descriptor = FlowTableHarness().descriptor()
        client.register(consumer)
        let items: [NStatMessageBuilder.Item] = [.domain("a.example"),
                                                 .parameters([(42, Array("https://a.example/x".utf8))])]
        let seeds = [build.added(1, .tcpUserland), build.update(1, .tcpUserland, descriptor, items: items),
                     build.update(2, .udpKernel, descriptor, received: 5, flags: NStat.closing), build.removed(1),
                     build.error(.query(1), ENOBUFS), build.counts(1, received: 1, sent: 1),
                     build.description(1, .tcpKernel, descriptor), build.added(1, .udpKernel) + build.removed(1)]
        var generator = SeededGenerator(seed: 0x6E73_7461_7466_757A)
        for round in 0..<10_000 {
            var datagram = seeds[Int.random(in: 0..<seeds.count, using: &generator)]
            if round % 5 == 0 {
                let count = Int.random(in: 16...600, using: &generator)
                datagram = (0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) }
            }
            for _ in 0..<Int.random(in: 1...4, using: &generator) {
                let offset = Int.random(in: 0..<datagram.count - 7, using: &generator)
                if Bool.random(using: &generator) {
                    datagram[offset] = UInt8.random(in: 0...255, using: &generator)
                } else {
                    datagram.put(Bool.random(using: &generator) ? UInt64.max : UInt64(1) << 63, at: offset & ~7)
                }
            }
            datagram.withUnsafeBytes { bytes in client.readQueue.sync { client.process(datagram: bytes) } }
        }
        XCTAssertEqual(client.status.state, .on)
    }

    /// Delivery completes a process whose exec the lineage table hears of after its flow, waiting for it, and
    /// counts a reaped process nothing knows.
    func testDeliveryCompletesTheProcess() throws {
        let reads = FakeFlowReads(), lineage = ProcessLineage(reader: nil, patience: 2)
        reads.processes[100] = FakeFlowReads.Process(upid: 5_000, pidversion: 7, signing: nil)
        let client = makeClient(reads: reads, lineage: lineage), build = NStatMessageBuilder()
        client.register(consumer)
        let key = ProcessKey(pid: 100, pidversion: 7)
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) {
            lineage.exec(ProcessProgram(key: key, path: "/usr/bin/nscurl", commandLine: "nscurl https://a.example",
                                        codesigningType: "PLATFORM"),
                         replacing: ProcessKey(pid: 100, pidversion: 6),
                         token: RawMessageFixture.auditToken(pid: 100, pidversion: 7), at: 0)
            lineage.told(upTo: .max)
        }
        var reaped = FlowTableHarness().descriptor()
        (reaped.pid, reaped.upid) = (300, 9)
        feed(client, build.added(1, .tcpUserland), build.update(1, .tcpUserland, FlowTableHarness().descriptor()),
             build.added(2, .tcpUserland), build.update(2, .tcpUserland, reaped))
        let first = try XCTUnwrap(consumer.records.all.first)
        XCTAssertEqual(first.process.program?.commandLine, "nscurl https://a.example")
        XCTAssertEqual(first.process.program?.codesigningType, "PLATFORM")
        XCTAssertEqual(client.status.counts.unresolved, 1)
    }

    /// Records come out in time order whatever order their updates came in, and a socket made long before it
    /// connected keeps that in its start, not its time.
    func testTimesComeOutInOrder() {
        let opened: Int64 = 401_000_000_000
        later.withLock { $0 = 401 }
        let client = makeClient(), build = NStatMessageBuilder(), harness = FlowTableHarness()
        client.register(consumer)
        var unconnected = harness.descriptor(start: 0, timestamp: 100, remote: nil)
        unconnected.state = 0
        let connected = harness.descriptor(start: 0, timestamp: opened + 300)
        let userland = harness.descriptor(start: opened + 100, timestamp: opened + 900)
        feed(client, build.added(2, .tcpKernel), build.update(2, .tcpKernel, unconnected), build.added(1, .tcpUserland),
             build.update(1, .tcpUserland, userland),
             build.update(2, .tcpKernel, connected, event: NStat.flowStateOutbound))
        let records = consumer.records.all
        XCTAssertEqual(records.map(\.process.pid), [100, 100])
        XCTAssertEqual(records.map(\.time.machTime), [410_000_000_900, 410_000_000_900])
        XCTAssertEqual(records.last?.start, FlowTableHarness.wall, "Made 401 s before it connected")
    }
}
