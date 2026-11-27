//
//  FlowClientHarness.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Clients on fake sockets
extension NetworkStatisticsClient {
    /// A client on fake sockets with no timer, which a test drains instead. pid 100 is a live process to read unless
    /// the reads say otherwise.
    ///
    /// - Parameters:
    ///   - darwin: The Darwin version.
    ///   - reads: The process reads.
    ///   - lineage: The lineage table.
    ///   - clock: The clocks, the table harness's start unless given.
    ///   - failures: The kernel's add failures.
    ///   - refusing: Refuse to open a socket?
    ///   - failing: The errno each socket answers a request with.
    ///   - sockets: Keeps every socket made, in order.
    /// - Returns: The client.
    static func fake(darwin: Int = 27, reads: FakeFlowReads = FakeFlowReads(), lineage: ProcessLineage? = nil,
                     clock: @escaping () -> FlowClock = { FlowTableHarness.clock() },
                     failures: @escaping () -> UInt32? = { nil }, refusing: Bool = false,
                     failing: @escaping ([UInt8]) -> Int32 = { _ in 0 },
                     sockets: Recorded<FakeFlowSocket> = Recorded()) -> NetworkStatisticsClient {
        reads.processes[100] = reads.processes[100] ?? FakeFlowReads.Process(upid: 5_000, pidversion: 7)
        return NetworkStatisticsClient(socket: {
            if refusing { throw FlowSocketError(code: EPERM) }
            let socket = FakeFlowSocket()
            socket.failRequests(failing)
            sockets.append(socket)
            return socket
        }, resolver: FlowProcessResolver(reads: reads.reads), fallback: { _ in nil }, lineage: { lineage },
           clock: clock, addFailures: failures, darwin: darwin, wakes: false)
    }
}


// MARK: - A client for capture sessions
/// A network statistics client on fake sockets for the tests of what records flows: capture sessions, the Security
/// Extension's services and `macmonitor stream`. It plays whole flows to the client's open socket and waits until
/// they're delivered.
final class FlowClientHarness {
    let sockets = Recorded<FakeFlowSocket>()
    let reads = FakeFlowReads()
    let client: NetworkStatisticsClient
    private let build = NStatMessageBuilder()
    /// Builds pid 100's descriptors.
    private let table = FlowTableHarness()
    /// The sockets made, and the last source reference played to the newest.
    private var played = (sockets: 0, reference: UInt64(0))
    /// The URL every flow records.
    static let url = "https://en.wikipedia.org/wiki/Endpoint_security"
    /// The URL every flow's request named, with a user, a password, a query and a fragment, which are never recorded.
    static let requested = "https://user:pw@en.wikipedia.org/wiki/Endpoint_security?token=secret#top"

    /// - Parameter refusing: Refuse to open a socket, as on a Mac whose network statistics can't be read?
    init(refusing: Bool = false) {
        client = .fake(reads: reads, refusing: refusing, sockets: sockets)
    }

    /// The socket the client has open, if any.
    var socket: FakeFlowSocket? {
        sockets.all.last.flatMap { $0.isClosed ? nil : $0 }
    }

    /// Hand datagrams to the open socket, and wait until they're read and delivered.
    ///
    /// - Parameter datagrams: The datagrams.
    /// - Returns: Whether they were delivered within 5 seconds.
    @discardableResult
    func feed(_ datagrams: [[UInt8]]) -> Bool {
        socket?.deliver(datagrams, waking: false)
        let drained = DispatchSemaphore(value: 0)
        client.drain { drained.signal() }
        return drained.wait(timeout: .now() + 5) == .success
    }

    /// A flow's whole life on the open socket, from a Network.framework TCP connection to Wikipedia with ``requested``:
    /// its add, the update that opens it, its closing update with its counts, and its removal.
    ///
    /// - Parameters:
    ///   - pid: Its process, which ``reads`` must know.
    ///   - lost: Sockets whose add the kernel couldn't queue just before it.
    /// - Returns: Its datagrams, one message each.
    func flow(pid: Int32 = 100, lost: UInt64 = 0) -> [[UInt8]] {
        if played.sockets != sockets.all.count { played = (sockets.all.count, 0) }
        played.reference += lost + 1
        let reference = played.reference
        var descriptor = table.descriptor()
        descriptor.pid = pid
        descriptor.upid = reads.processes[pid]?.upid ?? 0
        var closing = descriptor
        closing.timestamp += 1_000
        return [build.added(reference, .tcpUserland),
                build.update(reference, .tcpUserland, descriptor,
                             items: [.domain("en.wikipedia.org"), .parameters([(3, Array("en.wikipedia.org".utf8)),
                                                                              (42, Array(Self.requested.utf8))])]),
                build.update(reference, .tcpUserland, closing, received: 36_385, sent: 3_059, flags: NStat.closing),
                build.removed(reference)]
    }

    /// Play whole flows, and wait until they're delivered.
    ///
    /// - Parameters:
    ///   - count: How many.
    ///   - pid: Their process.
    /// - Returns: Whether they were delivered within 5 seconds.
    @discardableResult
    func play(_ count: Int = 1, pid: Int32 = 100) -> Bool {
        feed((0..<count).flatMap { _ in flow(pid: pid) })
    }
}
