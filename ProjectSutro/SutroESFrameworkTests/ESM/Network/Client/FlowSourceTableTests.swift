//
//  FlowSourceTableTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The source table
/// Pins every step of a source's life in the table: which sources become flows and when, which are adopted or
/// skipped, a record's values and times, and what's counted when the kernel drops a message.
final class FlowSourceTableTests: XCTestCase {
    /// A userland TCP flow opens at its first update, the reply to the add's query, with its process, ends, host,
    /// URL, site and direction, and closes with the same identifier and its final counts.
    func testAUserlandFlowOpensAndCloses() throws {
        let harness = FlowTableHarness()
        let build = harness.build, descriptor = harness.descriptor()
        let parameters: [(UInt8, [UInt8])] = [(3, Array("en.wikipedia.org".utf8)), (34, Array("wikipedia.org".utf8)),
                                              (42, Array("https://en.wikipedia.org/wiki/Endpoint_security?a=b".utf8))]
        harness.feed(build.added(1, .tcpUserland))
        XCTAssertEqual(harness.queries, [.query(1)])
        harness.feed(build.update(1, .tcpUserland, descriptor, items: [.domain("tracker.example"),
                                                                        .parameters(parameters)]))
        let opened = try XCTUnwrap(harness.records.first)
        XCTAssertEqual(opened.kind, .opened)
        XCTAssertEqual(opened.remote, FlowEndpoint(address: "198.35.26.224", port: 443))
        XCTAssertEqual(opened.local, FlowEndpoint(address: "192.168.64.2", port: 49_310))
        XCTAssertEqual([opened.family, opened.type, opened.proto], [AF_INET, SOCK_STREAM, IPPROTO_TCP])
        XCTAssertEqual(opened.hostname, "en.wikipedia.org")
        XCTAssertEqual(opened.url, "https://en.wikipedia.org/wiki/Endpoint_security?a=b")
        XCTAssertEqual(opened.firstPartySite, "wikipedia.org")
        XCTAssertEqual(opened.direction, .outbound)
        XCTAssertEqual(opened.process.key, ProcessKey(pid: 100, pidversion: 7))
        XCTAssertEqual(opened.process.program?.path, "/usr/bin/nscurl")
        XCTAssertEqual(opened.start, FlowTableHarness.wall + 100)
        XCTAssertEqual(opened.time, FlowTime(machTime: 9_000_000_200, wall: FlowTableHarness.wall + 200))
        XCTAssertNil(opened.bytesIn)
        var closing = descriptor
        closing.timestamp += 5_000
        harness.feed(build.update(1, .tcpUserland, closing, received: 36_385, sent: 3_059, flags: NStat.closing),
                     build.removed(1))
        let closed = try XCTUnwrap(harness.records.last)
        XCTAssertEqual(closed.kind, .closed)
        XCTAssertEqual(closed.identifier, opened.identifier)
        XCTAssertEqual([closed.bytesIn, closed.bytesOut], [36_385, 3_059])
        XCTAssertEqual(closed.time.machTime, 9_000_005_200)
        XCTAssertEqual(closed.url, opened.url, "The first update's items stay")
        XCTAssertTrue(harness.table.sources.isEmpty)
    }

    /// A kernel TCP socket is added at `socket()`, with no remote end. It becomes a flow at the first update after it
    /// connects, stamped with that update's time, and isn't polled after. A listener never does, and isn't polled.
    func testAKernelSocketOpensWhenItConnects() {
        let harness = FlowTableHarness()
        let build = harness.build
        var descriptor = harness.descriptor(remote: nil)
        descriptor.state = 0
        harness.feed(build.added(2, .tcpKernel), build.update(2, .tcpKernel, descriptor))
        XCTAssertTrue(harness.records.isEmpty)
        let connected = harness.descriptor(timestamp: 900_000)
        harness.feed(build.update(2, .tcpKernel, connected, event: NStat.flowStateOutbound))
        XCTAssertEqual(harness.records.map(\.kind), [.opened])
        XCTAssertEqual(harness.records.first?.time.machTime, 9_000_900_000)
        var listener = harness.descriptor()
        listener.state = 1
        harness.feed(build.added(3, .tcpKernel), build.update(3, .tcpKernel, listener))
        XCTAssertEqual(harness.records.count, 1)
        for later in [0.2, 2.2, 4.2] {
            harness.at(later)
            _ = harness.table.poll()
        }
        XCTAssertEqual(harness.queries, [.query(2), .query(3)], "Only the adds' queries")
    }

    /// A kernel TCP socket's host is read at the update it connects in, though its first update had none. A program
    /// that looks its host up after `socket()` connects at a poll.
    func testAKernelSocketsHostIsReadWhenItConnects() throws {
        let harness = FlowTableHarness()
        let build = harness.build
        var descriptor = harness.descriptor(remote: nil)
        descriptor.state = 0
        harness.feed(build.added(2, .tcpKernel), build.update(2, .tcpKernel, descriptor))
        harness.feed(build.update(2, .tcpKernel, harness.descriptor(timestamp: 500_000),
                                  items: [.domain("example.com")]))
        let opened = try XCTUnwrap(harness.records.first)
        XCTAssertEqual(opened.hostname, "example.com")
        let other: [NStatMessageBuilder.Item] = [.domain("other.test")]
        harness.feed(build.update(2, .tcpKernel, harness.descriptor(timestamp: 900_000), items: other),
                     build.update(2, .tcpKernel, harness.descriptor(timestamp: 950_000), flags: NStat.closing,
                                  items: other), build.removed(2))
        XCTAssertEqual(harness.records.map(\.hostname), ["example.com", "example.com"], "The host it opened with stays")
    }

    /// A loopback flow and one past 200 opened in a second are skipped, counted, and never closed either. So is a
    /// loopback flow open before the client started.
    func testLoopbackAndBudgetSkip() {
        let harness = FlowTableHarness()
        let build = harness.build
        harness.feed(build.added(1, .tcpUserland),
                     build.update(1, .tcpUserland, harness.descriptor(remote: .init(address: "127.0.0.1", port: 80))))
        var looped = harness.descriptor()
        looped.ifnetProperties = 0x2
        harness.feed(build.added(2, .tcpUserland), build.update(2, .tcpUserland, looped), build.removed(1))
        XCTAssertEqual(harness.table.counts.loopback, 2)
        XCTAssertTrue(harness.records.isEmpty)
        XCTAssertEqual(harness.reads.identityReads, 0, "A loopback socket's process is never read")
        for reference in UInt64(10)..<211 {
            harness.feed(build.added(reference, .tcpUserland),
                         build.update(reference, .tcpUserland, harness.descriptor()))
        }
        XCTAssertEqual(harness.records.count, 200)
        XCTAssertEqual(harness.table.counts.overBudget, 1)
        harness.feed(build.removed(210))
        XCTAssertEqual(harness.records.count, 200, "A skipped flow's close isn't recorded")
        harness.at(1)
        harness.feed(build.added(300, .tcpUserland), build.update(300, .tcpUserland, harness.descriptor()))
        XCTAssertEqual(harness.records.count, 201, "The next second has room")
        let local = FlowTableHarness(), loopback = NStatMessageBuilder.Endpoint(address: "127.0.0.1", port: 80)
        local.feed(local.build.added(1, .tcpUserland),
                   local.build.update(1, .tcpUserland, local.descriptor(start: -500, remote: loopback)),
                   local.build.removed(1))
        XCTAssertTrue(local.records.isEmpty, "A local flow open before the client started isn't adopted either")
    }

    /// A connection to the Mac's own address is local, though it opens before it's known to go through loopback, as
    /// from a socket bound to that address. A flow that goes local after it opens closes when the kernel says its
    /// filter held back the closing update, without counts, and that isn't a loss.
    func testAFlowThatGoesLocalIsntALoss() {
        let harness = FlowTableHarness()
        let build = harness.build, own = NStatMessageBuilder.Endpoint(address: "192.168.64.2", port: 8_080)
        harness.feed(build.added(1, .tcpKernel), build.update(1, .tcpKernel, harness.descriptor(remote: own)),
                     build.removed(1, flags: NStat.closedAfterFilter))
        XCTAssertTrue(harness.records.isEmpty)
        XCTAssertEqual(harness.table.counts.loopback, 1)
        harness.feed(build.added(2, .tcpKernel), build.update(2, .tcpKernel, harness.descriptor()),
                     build.removed(2, flags: NStat.closedAfterFilter))
        XCTAssertEqual(harness.records.map(\.kind), [.opened, .closed])
        XCTAssertNil(harness.records.last?.bytesIn)
        XCTAssertEqual(harness.table.counts.loopback, 2)
        XCTAssertEqual(harness.table.counts.closedWithoutCounts, 0)
    }

    /// A flow open before the client started is adopted: only its close is recorded, with its start. A kernel
    /// socket made before but connected after does open.
    func testAFlowOpenBeforeIsAdopted() {
        let harness = FlowTableHarness()
        let build = harness.build
        harness.feed(build.added(1, .tcpUserland), build.update(1, .tcpUserland, harness.descriptor(start: -500)))
        XCTAssertTrue(harness.records.isEmpty)
        harness.feed(build.removed(1))
        XCTAssertEqual(harness.records.map(\.kind), [.closed])
        XCTAssertEqual(harness.records.first?.start, FlowTableHarness.wall - 500)
        var unconnected = harness.descriptor(start: -500, remote: nil)
        unconnected.state = 0
        harness.feed(build.added(2, .tcpKernel), build.update(2, .tcpKernel, unconnected),
                     build.update(2, .tcpKernel, harness.descriptor(start: -500, timestamp: 400)))
        XCTAssertEqual(harness.records.map(\.kind), [.closed, .opened])
    }

    /// A UDP socket is a flow only at its removal: when it carried bytes to a known remote end, and no subflow
    /// carried them for it.
    func testAUDPSocketIsAFlowAtItsRemoval() {
        let harness = FlowTableHarness()
        let build = harness.build, dns = NStatMessageBuilder.Endpoint(address: "192.168.64.1", port: 53)
        let socket = harness.descriptor(remote: dns, local: .init(address: "192.168.64.2", port: 54_326))
        harness.feed(build.added(1, .udpKernel), build.update(1, .udpKernel, socket))
        XCTAssertTrue(harness.records.isEmpty)
        harness.feed(build.update(1, .udpKernel, socket, received: 90, sent: 40, flags: NStat.closing),
                     build.removed(1))
        XCTAssertEqual(harness.records.map(\.kind), [.opened, .closed])
        XCTAssertEqual(harness.records.map(\.type), [SOCK_DGRAM, SOCK_DGRAM])
        XCTAssertEqual(harness.records.last?.bytesIn, 90)
        harness.records = []
        harness.feed(build.added(2, .udpKernel), build.update(2, .udpKernel, socket), build.removed(2))
        XCTAssertTrue(harness.records.isEmpty, "No bytes")
        harness.feed(build.added(3, .udpKernel), build.added(4, .udpSubflow), build.update(4, .udpSubflow, socket),
                     build.update(3, .udpKernel, socket, received: 5, flags: NStat.closing), build.removed(3))
        XCTAssertEqual(harness.records.map(\.kind), [.opened], "Only the subflow")
    }

    /// Lost adds are counted by the jumps in source references, and a source whose add was lost is made from its
    /// first update, counting the gap before it. An unanswered query is polled. A check that finds a flow gone
    /// closes it without its counts, as does a removal with no closing update, at the moment it's read.
    func testLossesAreCounted() {
        let harness = FlowTableHarness()
        let build = harness.build
        harness.feed(build.added(1, .tcpUserland), build.added(5, .tcpUserland), build.added(6, .tcpUserland))
        XCTAssertEqual(harness.table.counts.lostSources, 3)
        XCTAssertTrue(harness.table.lossSignalled)
        harness.table.lossSignalled = false
        harness.queries = []
        harness.feed(build.error(.query(5), ENOBUFS), build.error(.query(6), ENOMEM), build.error(.query(1), ENOENT))
        XCTAssertEqual(harness.table.counts.queryFailures, 2)
        harness.at(0.1)
        _ = harness.table.poll()
        XCTAssertEqual(harness.queries.count, 2)
        XCTAssertTrue(harness.queries.contains(.query(5)) && harness.queries.contains(.query(6)), "Both are polled")
        harness.at(0)
        harness.feed(build.update(9, .tcpUserland, harness.descriptor()),
                     build.update(1, .tcpUserland, harness.descriptor()))
        XCTAssertEqual(harness.table.counts.lateSources, 1)
        XCTAssertEqual(harness.table.counts.lostSources, 5, "The gap before the late source counts too")
        XCTAssertTrue(harness.table.lossSignalled, "The late source's own add was lost")
        XCTAssertEqual(harness.records.count, 2)
        harness.feed(build.added(10, .tcpUserland))
        XCTAssertEqual(harness.table.counts.lostSources, 5)
        harness.feed(build.error(.check(9), ENOENT), build.removed(1, flags: NStat.closedAfterDrop))
        XCTAssertEqual(harness.records.map(\.kind), [.opened, .opened, .closed, .closed])
        XCTAssertEqual(harness.records.suffix(2).map(\.bytesIn), [nil, nil])
        XCTAssertEqual(harness.records.last?.time.machTime, 9_000_000_200, "Not before the last record")
        XCTAssertEqual(harness.table.counts.closedWithoutCounts, 2)
        XCTAssertEqual(harness.table.counts.closedAfterDrop, 1)
        harness.feed(build.error(.add(.udpUserland), EPERM))
        XCTAssertEqual(harness.table.providersOff, [.udpUserland: EPERM])
    }

    /// A table at its capacity keeps no more sources, whether their add came or only a later update.
    func testATableAtItsCapacityTakesNoMore() {
        let harness = FlowTableHarness()
        let build = harness.build, capacity = UInt64(FlowSourceTable.capacity)
        for reference in 1...capacity {
            harness.feed(build.added(reference, .udpKernel))
        }
        harness.feed(build.added(capacity + 1, .udpKernel),
                     build.update(capacity + 2, .tcpUserland, harness.descriptor()))
        XCTAssertEqual(harness.table.sources.count, FlowSourceTable.capacity)
        XCTAssertEqual(harness.table.counts.ignoredSources, 2)
        XCTAssertEqual(harness.table.counts.lateSources, 0)
        XCTAssertTrue(harness.records.isEmpty)
    }

    /// Each source is kept small, and the table gives its storage back once most of its sources are gone, so a
    /// storm of sockets leaves no memory behind.
    func testTheTableGivesBackItsStorage() {
        XCTAssertLessThanOrEqual(MemoryLayout<FlowSource>.stride, 192)
        let harness = FlowTableHarness()
        let build = harness.build, count = UInt64(FlowSourceTable.capacity)
        for reference in 1...count {
            harness.feed(build.added(reference, .udpKernel),
                         build.update(reference, .udpKernel, harness.descriptor(remote: nil)))
        }
        let full = harness.table.sources.capacity
        for reference in 1...count {
            harness.feed(build.removed(reference))
        }
        XCTAssertTrue(harness.table.sources.isEmpty)
        XCTAssertLessThanOrEqual(harness.table.sources.capacity, full / 8)
    }

    /// A kernel that never took the updates mode closes a source with closing counts and a description: the flow
    /// closes with those counts.
    func testLegacyClosingMessages() {
        let harness = FlowTableHarness(darwin: 22)
        let build = harness.build
        harness.feed(build.added(1, .tcpKernel), build.counts(1, received: 700, sent: 70),
                     build.description(1, .tcpKernel, harness.descriptor()), build.removed(1))
        XCTAssertEqual(harness.records.map(\.kind), [.opened, .closed])
        XCTAssertEqual([harness.records.last?.bytesIn, harness.records.last?.bytesOut], [700, 70])
    }

    /// Record times never go back, though updates can come out of their order. A delegated socket names the app it
    /// acts for, and an IPv4-mapped remote end is written as IPv4 with the socket's family.
    func testRecordValues() {
        let harness = FlowTableHarness()
        let build = harness.build
        harness.reads.processes[200] = FakeFlowReads.Process(upid: 6_000, pidversion: 3, path: "/usr/bin/curl")
        var delegated = harness.descriptor(timestamp: 900,
                                           remote: .init(address: "::ffff:198.35.26.224", port: 443), local: nil)
        (delegated.epid, delegated.eupid) = (200, 6_000)
        harness.feed(build.added(1, .quicUserland), build.update(1, .quicUserland, delegated))
        harness.feed(build.added(2, .tcpUserland), build.update(2, .tcpUserland, harness.descriptor(timestamp: 300)))
        XCTAssertEqual(harness.records.map(\.time.machTime), [9_000_000_900, 9_000_000_900])
        let quic = harness.records[0]
        XCTAssertEqual(quic.sourceApp?.key, ProcessKey(pid: 200, pidversion: 3))
        XCTAssertEqual(quic.remote.address, "198.35.26.224")
        XCTAssertEqual([quic.family, quic.type, quic.proto], [AF_INET6, SOCK_DGRAM, IPPROTO_UDP])
        XCTAssertNil(quic.local)
        XCTAssertFalse(quic.isOwn)
    }

    /// A delegated TCP socket gives its effective pid with no unique ID, as com.apple.WebKit.Networking's for Safari
    /// and trustd's for nscurl do on macOS 13 and 27. Its record names the app running with that pid, with its
    /// executable and signing values.
    func testADelegatedSocketWithNoUniqueIDNamesItsApp() throws {
        let harness = FlowTableHarness()
        let build = harness.build
        harness.reads.processes[200] = FakeFlowReads.Process(
            upid: 6_000, pidversion: 3, path: "/Applications/Safari.app/Contents/MacOS/Safari",
            signing: FlowSigning(signingID: "com.apple.Safari", teamID: nil, type: .platform))
        var delegated = harness.descriptor()
        (delegated.epid, delegated.eupid) = (200, 0)
        harness.feed(build.added(1, .tcpUserland), build.update(1, .tcpUserland, delegated))
        let app = try XCTUnwrap(harness.records.first?.sourceApp)
        XCTAssertEqual(app.state, .live)
        XCTAssertEqual(app.key, ProcessKey(pid: 200, pidversion: 3))
        XCTAssertEqual(app.program?.path, "/Applications/Safari.app/Contents/MacOS/Safari")
        XCTAssertEqual(app.program?.signingID, "com.apple.Safari")
        XCTAssertEqual(app.program?.codesigningType, CodeSigningType.platform.rawValue)
    }

    /// A socket no process has used since it was made names pid 0 and its owner as the effective pid, as
    /// mDNSResponder's multicast sockets do on macOS 13. Its record names the owner as its process, with no app it
    /// acts for.
    func testAnUnusedSocketNamesItsOwner() {
        let harness = FlowTableHarness()
        let build = harness.build
        harness.reads.processes[216] = FakeFlowReads.Process(upid: 6_216, pidversion: 449,
                                                             path: "/usr/sbin/mDNSResponder")
        var owned = harness.descriptor()
        (owned.pid, owned.upid, owned.epid, owned.eupid, owned.name) = (0, 0, 216, 6_216, "")
        harness.feed(build.added(1, .tcpUserland), build.update(1, .tcpUserland, owned))
        XCTAssertEqual(harness.records.first?.process.key, ProcessKey(pid: 216, pidversion: 449))
        XCTAssertNil(harness.records.first?.sourceApp)
    }

    /// An update over 2,048 bytes, which only a source's own query brings, is read whole: its URL is cut at the
    /// limit, not where a 2,048-byte message would end.
    func testALongUpdateIsRead() {
        let harness = FlowTableHarness()
        let url = "https://en.wikipedia.org/wiki/" + String(repeating: "how-to-", count: 300)
        let update = harness.build.update(1, .tcpUserland, harness.descriptor(),
                                          items: [.domain(""), .parameters([(42, Array(url.utf8))])])
        XCTAssertGreaterThan(update.count, 2_048)
        harness.feed(harness.build.added(1, .tcpUserland), update)
        XCTAssertEqual(harness.records.first?.url, String(url.prefix(FlowURL.limit)), "Cut at the limit only")
    }
}
