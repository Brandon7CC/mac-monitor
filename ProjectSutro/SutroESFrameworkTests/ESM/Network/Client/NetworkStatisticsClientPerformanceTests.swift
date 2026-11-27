//
//  NetworkStatisticsClientPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The client's cost
/// Times what the client's read queue does: a whole flow's messages, a wake with nothing due, and reading a process
/// with the resolver's cache warm and cold, on this Mac's live process reads.
final class NetworkStatisticsClientPerformanceTests: PerformanceTestCase {
    /// A client on a fake socket, with pid 100 to read, a clock fixed where the test puts it, and no timer.
    ///
    /// - Parameters:
    ///   - darwin: The Darwin version.
    ///   - later: The clock's seconds after the harness's start.
    /// - Returns: The client, with a consumer that drops what it's handed.
    private func makeClient(darwin: Int = 27, at later: Double = 0) -> NetworkStatisticsClient {
        let client = NetworkStatisticsClient.fake(darwin: darwin, clock: { FlowTableHarness.clock(later) })
        client.register(Sink())
        return client
    }

    /// One flow's life, the way the read queue takes it: its add, its first update with a domain and NECP
    /// parameters, its closing update and its removal, each its own datagram. Every flow is new, so each makes
    /// both its records, and the clock moves a second every 200 flows, the rate budget. Prints the allocations a
    /// flow makes.
    func testProcessingAFlow() throws {
        let flows = 1_000, perSecond = FlowSourceTable.budget, build = NStatMessageBuilder()
        let harness = FlowTableHarness()
        let parameters: [(UInt8, [UInt8])] = [(3, Array("en.wikipedia.org".utf8)), (34, Array("wikipedia.org".utf8)),
                                              (42, Array("https://en.wikipedia.org/wiki/Endpoint_security".utf8))]
        let datagrams = (UInt64(1)...UInt64(flows)).map { reference -> [[UInt8]] in
            let descriptor = harness.descriptor(start: 100)
            var closing = descriptor
            closing.timestamp += 1_000
            return [build.added(reference, .tcpUserland),
                    build.update(reference, .tcpUserland, descriptor, items: [.domain("en.wikipedia.org"),
                                                                              .parameters(parameters)]),
                    build.update(reference, .tcpUserland, closing, received: 36_385, sent: 3_059, flags: NStat.closing),
                    build.removed(reference)]
        }
        /// Hand every flow to a client.
        func feed(_ client: NetworkStatisticsClient) {
            for (index, flow) in datagrams.enumerated() {
                if index % perSecond == 0 { client.table?.clock = FlowTableHarness.clock(Double(index / perSecond)) }
                for datagram in flow {
                    datagram.withUnsafeBytes { client.process(datagram: $0) }
                }
            }
        }
        try benchmark("network.process.flow", unit: "flow", operations: flows, setUp: { makeClient() }) { client in
            feed(client)
            let counts = client.status.counts
            guard counts.closedWithoutCounts == 0, counts.overBudget == 0, client.status.openSources == 0 else {
                throw BenchmarkFailure("Every flow opened, and closed with its counts")
            }
        }
        let client = makeClient()
        let allocations = AllocationCounter.counting { feed(client) }
        print(String(format: "[performance] network.process.flow: %.1f allocations/flow",
                     Double(allocations) / Double(flows)))
    }

    /// A wake with nothing due while 10,000 sources wait to be polled: Darwin 22's unconnected kernel TCP sockets.
    func testAnIdleWake() throws {
        let sources = 10_000, wakes = 1_000, build = NStatMessageBuilder(darwin: 22)
        var unconnected = FlowTableHarness().descriptor(remote: nil)
        unconnected.state = 0
        let datagrams = (UInt64(1)...UInt64(sources)).flatMap { reference in
            [build.added(reference, .tcpKernel), build.update(reference, .tcpKernel, unconnected)]
        }
        try benchmark("network.wake.idle", unit: "wake", operations: wakes, setUp: { () -> NetworkStatisticsClient in
            let client = makeClient(darwin: 22, at: 0.05)
            for datagram in datagrams {
                datagram.withUnsafeBytes { client.process(datagram: $0) }
            }
            return client
        }) { client in
            for _ in 0..<wakes { client.tick() }
            guard client.status.openSources == sources else { throw BenchmarkFailure("Every source is kept") }
        }
    }

    /// Reading a live process the resolver's cache has: this test process.
    func testResolvingACachedProcess() throws {
        let pid = getpid(), reads = 1_000
        let upid = try XCTUnwrap(FlowProcessResolver.Reads.live.identity(pid)).upid
        let resolver = FlowProcessResolver()
        try benchmark("network.resolve.hit", unit: "process", operations: reads) {
            for _ in 0..<reads where resolver.resolve(pid: pid, upid: upid, name: "xctest").state != .live {
                throw BenchmarkFailure("This process reads as live")
            }
        }
    }

    /// Reading a live process the resolver's cache doesn't have: its identity, parent, session, token, path and
    /// signing values, from this Mac's kernel.
    func testResolvingAnUncachedProcess() throws {
        let pid = getpid(), reads = 1_000
        let upid = try XCTUnwrap(FlowProcessResolver.Reads.live.identity(pid)).upid
        let resolver = FlowProcessResolver()
        try benchmark("network.resolve.miss", unit: "process", operations: reads) {
            for _ in 0..<reads {
                resolver.removeAll()
                guard resolver.resolve(pid: pid, upid: upid, name: "xctest").program?.path != nil else {
                    throw BenchmarkFailure("This process's path reads")
                }
            }
        }
    }
}


/// Takes records and drops them.
private final class Sink: FlowConsumer {
    /// - Parameter record: A record.
    func handle(_ record: FlowRecord) {}
}
