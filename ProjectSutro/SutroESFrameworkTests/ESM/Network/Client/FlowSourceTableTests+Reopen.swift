//
//  FlowSourceTableTests+Reopen.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Reopens
extension FlowSourceTableTests {
    /// A table that replaces another carries its flows on: a source seen again keeps its identifier and stage,
    /// and one not seen again is given up as closed in between.
    func testAReplacementCarriesFlowsOn() {
        let first = FlowTableHarness()
        first.feed(first.build.added(1, .tcpUserland), first.build.update(1, .tcpUserland, first.descriptor()))
        var other = first.descriptor()
        other.upid = 5_001
        first.feed(first.build.added(2, .tcpUserland), first.build.update(2, .tcpUserland, other))
        let second = FlowTableHarness(replacing: first)
        second.feed(second.build.added(1, .tcpUserland), second.build.update(1, .tcpUserland, first.descriptor()),
                    second.build.removed(1))
        XCTAssertEqual(second.records.map(\.kind), [.closed])
        XCTAssertEqual(second.records.first?.identifier, first.records.first?.identifier)
        second.table.dropInherited()
        XCTAssertEqual(second.table.counts.closedDuringReopen, 1)
        XCTAssertEqual(second.table.counts.lostSources, first.table.counts.lostSources)
    }

    /// A socket made before capture is recorded the same whether the client reopened or not: a pending UDP socket
    /// only by its close, and a kernel TCP socket that connects across the reopen by its opening.
    func testAReopenKeepsWhatWasMadeBeforeCapture() {
        let first = FlowTableHarness()
        let build = first.build, dns = NStatMessageBuilder.Endpoint(address: "192.168.64.1", port: 53)
        let udp = first.descriptor(start: -500, remote: dns)
        var unconnected = first.descriptor(start: -400, remote: nil)
        unconnected.state = 0
        first.feed(build.added(1, .udpKernel), build.update(1, .udpKernel, udp), build.added(2, .tcpKernel),
                   build.update(2, .tcpKernel, unconnected))
        let second = FlowTableHarness(replacing: first)
        second.feed(build.added(1, .udpKernel), build.update(1, .udpKernel, udp), build.added(2, .tcpKernel),
                    build.update(2, .tcpKernel, first.descriptor(start: -400, timestamp: 300)),
                    build.update(1, .udpKernel, udp, received: 90, sent: 40, flags: NStat.closing), build.removed(1))
        XCTAssertTrue(first.records.isEmpty)
        XCTAssertEqual(second.records.map(\.kind), [.opened, .closed])
        XCTAssertEqual(second.records.map(\.proto), [IPPROTO_TCP, IPPROTO_UDP])
    }

    /// A UDP socket whose subflow was recorded before a reopen isn't recorded again when it's removed after it.
    func testAReopenKeepsTheSubflowsSeen() {
        let first = FlowTableHarness()
        let build = first.build, dns = NStatMessageBuilder.Endpoint(address: "192.168.64.1", port: 53)
        let socket = first.descriptor(remote: dns, local: .init(address: "192.168.64.2", port: 54_326))
        first.feed(build.added(1, .udpKernel), build.update(1, .udpKernel, socket), build.added(2, .udpSubflow),
                   build.update(2, .udpSubflow, socket), build.removed(2))
        XCTAssertEqual(first.records.map(\.kind), [.opened, .closed])
        let second = FlowTableHarness(replacing: first)
        second.feed(build.added(1, .udpKernel), build.update(1, .udpKernel, socket),
                    build.update(1, .udpKernel, socket, received: 90, flags: NStat.closing), build.removed(1))
        XCTAssertTrue(second.records.isEmpty, "Only the subflow")
    }
}
