//
//  NetworkStatisticsClientTests+Loss.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - Losses and reopens
extension NetworkStatisticsClientTests {
    /// After a loss, the open flows are checked 200 at a time, 0.1 s apart however often the client wakes, while
    /// under 1 MB is waiting. Each step here wakes it twice at the same moment.
    func testTheLossCheckIsSpread() throws {
        let client = makeClient(), build = NStatMessageBuilder()
        client.register(consumer)
        let adopted = (UInt64(1)...450).map { build.added($0, .tcpUserland)
            + build.update($0, .tcpUserland, FlowTableHarness().descriptor(start: -100)) }
        let socket = try XCTUnwrap(sockets.all.last)
        socket.waiting = 2 << 20
        feed(client, all: adopted + [build.added(460, .tcpUserland)])
        XCTAssertEqual(client.status.flows, 450)
        let checks = { socket.queries.filter { if case .check = $0 { true } else { false } }.count }
        XCTAssertEqual(checks(), 0, "Too much is waiting")
        socket.waiting = 0
        var counted: [Int] = []
        for _ in 0..<5 {
            later.withLock { $0 += 0.15 }
            feed(client)
            counted.append(checks())
        }
        XCTAssertEqual(counted, [200, 400, 450, 450, 450])
    }

    /// On Darwin 22, adds another client couldn't queue are counted apart from the client's own lost sources, and
    /// answered by reopening. Flows open across it keep their identifiers. Darwin 24 never looks.
    func testAnotherClientsFailuresReopen() throws {
        let failures = OSAllocatedUnfairLock(initialState: [UInt32(100), 130])
        let client = makeClient(darwin: 22, failures: { failures.withLock { $0.isEmpty ? nil : $0.removeFirst() } })
        let build = NStatMessageBuilder(darwin: 22), descriptor = FlowTableHarness().descriptor()
        client.register(consumer)
        feed(client, build.added(1, .tcpUserland), build.update(1, .tcpUserland, descriptor),
             build.added(12, .tcpUserland))
        later.withLock { $0 += 5 }
        feed(client)
        XCTAssertEqual(client.status.counts.otherClientFailures, 20)
        XCTAssertEqual(client.status.counts.reopens, 1)
        XCTAssertEqual(sockets.all.count, 2)
        XCTAssertTrue(sockets.all[0].isClosed)
        XCTAssertEqual(sockets.all[1].sent.all.count, 7, "The new socket asks for every source")
        feed(client, build.added(3, .tcpUserland), build.update(3, .tcpUserland, descriptor), build.removed(3))
        XCTAssertEqual(consumer.records.all.map(\.kind), [.opened, .closed])
        XCTAssertEqual(Set(consumer.records.all.map(\.identifier)).count, 1)

        var looked = 0
        let modern = makeClient(darwin: 24, failures: { looked += 1; return 0 })
        modern.register(FlowCollector())
        feed(modern)
        XCTAssertEqual(looked, 0)
    }

    /// A datagram cut short, or one whose messages can't be walked, may have taken a removal with it: each
    /// starts a check of the open flows.
    func testADamagedDatagramStartsACheck() throws {
        let client = makeClient(), build = NStatMessageBuilder()
        client.register(consumer)
        feed(client, build.added(1, .tcpUserland), build.update(1, .tcpUserland, FlowTableHarness().descriptor()))
        let socket = try XCTUnwrap(sockets.all.last)
        let checks = { socket.queries.filter { $0 == .check(1) }.count }
        var walkedPast = build.removed(2)
        walkedPast.put(UInt16(200), at: 12)
        feed(client, walkedPast)
        XCTAssertEqual(client.status.counts.malformed, 1)
        XCTAssertEqual(checks(), 1)
        later.withLock { $0 += 10 }
        feed(client, [UInt8](repeating: 0, count: 70_000))
        XCTAssertEqual(client.status.counts.truncated, 1)
        XCTAssertEqual(checks(), 2)
    }

    /// A reopen reads everything the old socket still holds before closing it, so no flow that closed in it loses
    /// its record.
    func testAReopenReadsTheOldSocketToTheEnd() throws {
        let failures = OSAllocatedUnfairLock(initialState: [UInt32(100), 130])
        let client = makeClient(darwin: 22, failures: { failures.withLock { $0.isEmpty ? nil : $0.removeFirst() } })
        let build = NStatMessageBuilder(darwin: 22), flows = UInt64(1_500)
        client.register(consumer)
        for batch in stride(from: UInt64(1), through: flows, by: 500) {
            feed(client, all: (batch..<batch + 500).flatMap { [build.added($0, .tcpUserland),
                build.update($0, .tcpUserland, FlowTableHarness().descriptor(start: -100))] })
        }
        let old = try XCTUnwrap(sockets.all.last)
        old.deliver((1...flows).flatMap { [build.update($0, .tcpUserland, FlowTableHarness().descriptor(start: -100),
                                                        flags: NStat.closing), build.removed($0)] }, waking: false)
        later.withLock { $0 += 5 }
        feed(client)
        XCTAssertEqual(client.status.counts.reopens, 1)
        XCTAssertTrue(old.isClosed)
        XCTAssertEqual(consumer.records.all.filter { $0.kind == .closed }.count, Int(flows))
        XCTAssertEqual(client.status.counts.closedWithoutCounts, 0)
    }

    /// Failures that go on as fast after a reopen as before it are an older client's, which a reopen doesn't
    /// help: the client reopens once, then waits longer each time.
    func testAnOlderClientsFailuresReopenOnce() {
        let client = makeClient(darwin: 22, failures: { [later] in UInt32(100 + 4 * later.withLock { $0 }) })
        client.register(consumer)
        for _ in 0..<40 {
            later.withLock { $0 += 5 }
            feed(client)
        }
        XCTAssertEqual(client.status.counts.reopens, 1)
        XCTAssertEqual(client.status.counts.otherClientFailures, 800)
    }
}
