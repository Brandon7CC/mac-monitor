//
//  FlowSource.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - A source
/// One socket the kernel reports (a source), as the client keeps it from its add to its removal. What its first
/// update says of its process is kept in ``Details``, out of line, so a source takes little of its table's storage.
struct FlowSource {
    /// Where it is on its way to being a flow.
    enum Stage {
        /// Not a flow yet. Its remote end isn't known, or it's a UDP socket, which is decided at its removal.
        case pending
        /// A flow whose opening was recorded.
        case open
        /// A flow that was open before the client started, recorded only when it closes.
        case adopted
        /// A flow that's never recorded, since it's loopback or past the rate budget.
        case skipped
    }

    /// What a source's first update says of its process, and its items from the first update that has any.
    final class Details {
        /// The socket's last user.
        let process: FlowProcess
        /// The process it acts for, when that's another.
        let sourceApp: FlowProcess?
        var items = FlowItems()

        /// - Parameters:
        ///   - process: The socket's last user.
        ///   - sourceApp: The process it acts for, when that's another.
        init(process: FlowProcess, sourceApp: FlowProcess? = nil) {
            (self.process, self.sourceApp) = (process, sourceApp)
        }
    }

    let provider: NStat.Provider
    var stage = Stage.pending
    var identifier: UUID?
    /// Read at its first update. `nil` until then.
    var details: Details?
    var upid: UInt64 = 0
    /// When the socket was made, in `mach_continuous_time` ticks.
    var start: UInt64 = 0
    var local = FlowAddress.none, remote = FlowAddress.none
    /// A TCP socket's state, `TCPS_LISTEN` (1) for a listener.
    var state: UInt32?
    var ifnetProperties: UInt32 = 0
    /// The kernel's byte totals, from its latest update.
    var received: UInt64 = 0, sent: UInt64 = 0
    /// Did its closing update come, with its final counts? Its time, in ticks, when it did.
    var closedAt: UInt64?
    /// Was it made before the client started?
    var isExisting = false
    /// How many times it was queried again, and when it's next due, in seconds of uptime.
    var polls = 0, nextPoll: TimeInterval = 0

    /// Is it a listener, which is never a flow? Its accepted connections are sources of their own.
    var isListener: Bool {
        state == 1
    }

    /// Is it a local connection, on the loopback interface, to a loopback address, or to its own address? A
    /// connection to its own address can open before it goes through loopback, as from a socket bound to it.
    var isLoopback: Bool {
        ifnetProperties & NStat.loopbackInterface != 0 || remote.isLoopback
            || (remote.bytes != .zero && remote.family == local.family && remote.bytes == local.bytes)
    }

    /// Which way it was opened, from the interface properties Darwin 23 and later set.
    var direction: FlowDirection? {
        if ifnetProperties & 0x0400_0000 != 0 { return .inbound }
        return ifnetProperties & 0x0800_0000 != 0 ? .outbound : nil
    }

    /// What tells it apart from any other socket after the client reopens. That's its provider, its process's unique
    /// ID and its creation tick.
    var match: Match {
        Match(provider: provider, upid: upid, start: start)
    }

    /// A source's identity across two sockets of the client.
    struct Match: Hashable {
        let provider: NStat.Provider
        let upid, start: UInt64
    }
}


extension FlowAddress {
    /// No address.
    static let none = FlowAddress(UnsafeRawBufferPointer(start: nil, count: 0), at: 0)

    /// The address as an endpoint.
    ///
    /// - Returns: The endpoint, or `nil` for no address.
    func endpoint() -> FlowEndpoint? {
        text().map { FlowEndpoint(address: $0, port: Int(port)) }
    }
}
