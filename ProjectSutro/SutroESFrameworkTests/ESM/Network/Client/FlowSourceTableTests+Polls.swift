//
//  FlowSourceTableTests+Polls.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/27/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Polls
extension FlowSourceTableTests {
    /// A poll stops once its source connects at a poll's reply, or turns out to be a listener, as a server's socket
    /// does when its first update came before `listen()`.
    func testPollsStopWhenTheSourceConnectsOrListens() {
        let harness = FlowTableHarness()
        let build = harness.build
        var unconnected = harness.descriptor(remote: nil)
        unconnected.state = 0
        harness.feed(build.added(2, .tcpKernel), build.update(2, .tcpKernel, unconnected),
                     build.added(3, .tcpKernel), build.update(3, .tcpKernel, unconnected))
        harness.queries = []
        harness.at(0.1)
        _ = harness.table.poll()
        XCTAssertEqual(harness.queries, [.query(2), .query(3)])
        var listening = harness.descriptor(remote: nil)
        listening.state = 1
        harness.feed(build.update(2, .tcpKernel, harness.descriptor(timestamp: 100_000_000)),
                     build.update(3, .tcpKernel, listening))
        XCTAssertEqual(harness.records.map(\.kind), [.opened])
        harness.queries = []
        for later in [2.1, 4.1, 6.1, 8.1] {
            harness.at(later)
            _ = harness.table.poll()
        }
        XCTAssertEqual(harness.queries, [], "Neither is polled again")
    }

    /// A pass the client holds back, while its socket has many bytes waiting, sends nothing and goes 0.1 s later.
    func testAHeldBackPassSendsNothing() throws {
        let harness = FlowTableHarness()
        var unconnected = harness.descriptor(remote: nil)
        unconnected.state = 0
        harness.feed(harness.build.added(2, .tcpKernel), harness.build.update(2, .tcpKernel, unconnected))
        harness.queries = []
        harness.at(0.1)
        XCTAssertEqual(try XCTUnwrap(harness.table.poll(sending: false)), FlowTableHarness.clock(0.2).seconds,
                       accuracy: 0.001)
        XCTAssertEqual(harness.queries, [])
        harness.at(0.2)
        _ = harness.table.poll()
        XCTAssertEqual(harness.queries, [.query(2)])
    }

    /// A pass sends at most 200 polls, and the rest go 0.1 s later.
    func testAPassSendsABatch() {
        let harness = FlowTableHarness()
        let build = harness.build
        var unconnected = harness.descriptor(remote: nil)
        unconnected.state = 0
        for reference in UInt64(1)...300 {
            harness.feed(build.added(reference, .tcpKernel), build.update(reference, .tcpKernel, unconnected))
        }
        harness.queries = []
        harness.at(0.1)
        XCTAssertEqual(try XCTUnwrap(harness.table.poll()), FlowTableHarness.clock(0.2).seconds, accuracy: 0.001)
        XCTAssertEqual(harness.queries.count, FlowSourceTable.pollBatch)
        harness.at(0.2)
        XCTAssertEqual(try XCTUnwrap(harness.table.poll()), FlowTableHarness.clock(2.1).seconds, accuracy: 0.001)
        let polled = harness.queries.compactMap { request -> UInt64? in
            guard case .query(let reference) = request else { return nil }
            return reference
        }
        XCTAssertEqual(Set(polled), Set(1...300), "Each source once")
    }

    /// A kernel TCP socket is polled until it connects: 0.1 s after its first update, then every 2 s, 5 times at most.
    /// A poll answered with `ENOENT` ends them, for a source the kernel no longer has or its filter holds back, as a
    /// loopback socket once it connects. Darwin 22 has no event at connect, and on macOS 27.2 Darwin 27's didn't come.
    func testAKernelSocketIsPolledUntilItConnects() {
        for darwin in [22, 27] {
            pollsAKernelSocket(darwin: darwin)
        }
    }

    /// Polls a kernel TCP socket on a Darwin version, for ``testAKernelSocketIsPolledUntilItConnects()``.
    ///
    /// - Parameter darwin: The Darwin version.
    private func pollsAKernelSocket(darwin: Int) {
        let harness = FlowTableHarness(darwin: darwin)
        var descriptor = harness.descriptor(remote: nil)
        descriptor.state = 0
        harness.feed(harness.build.added(2, .tcpKernel), harness.build.update(2, .tcpKernel, descriptor))
        harness.queries = []
        var sent: [Double] = []
        for tenth in 0...130 {
            harness.at(Double(tenth) / 10)
            let before = harness.queries.count
            _ = harness.table.poll()
            if harness.queries.count > before { sent.append(Double(tenth) / 10) }
        }
        XCTAssertEqual(sent.count, 5, "Darwin \(darwin)")
        XCTAssertEqual(sent.first ?? 0, 0.1, accuracy: 0.11, "Darwin \(darwin)")
        for (earlier, later) in zip(sent, sent.dropFirst()) {
            XCTAssertEqual(later - earlier, 2, accuracy: 0.11)
        }
        XCTAssertEqual(harness.queries, Array(repeating: .query(2), count: 5))
        harness.queries = []
        harness.feed(harness.build.added(3, .tcpKernel), harness.build.update(3, .tcpKernel, descriptor))
        for tenth in 131...260 {
            if tenth == 140 { harness.feed(harness.build.error(.query(3), ENOENT)) }
            harness.at(Double(tenth) / 10)
            _ = harness.table.poll()
        }
        XCTAssertEqual(harness.queries, [.query(3), .query(3)], "Its add's query and one poll, Darwin \(darwin)")
    }
}
