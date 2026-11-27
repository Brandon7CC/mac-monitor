//
//  FlowRecord.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Flow records
/// A network flow that opened or closed, as the client hands it to each consumer (``NetworkStatisticsClient``).
struct FlowRecord: Sendable {
    /// Whether the flow opened or closed.
    enum Kind: Sendable {
        case opened, closed
    }

    let kind: Kind
    /// Made when the flow opens or is adopted, and the same in both records.
    let identifier: UUID
    /// The socket's last user, completed on delivery.
    var process: FlowProcess
    /// The process the socket acts for, when that's another.
    var sourceApp: FlowProcess?
    /// Is it the Security Extension's own socket?
    let isOwn: Bool
    let local: FlowEndpoint?
    let remote: FlowEndpoint
    /// `AF_INET` or `AF_INET6`, `SOCK_STREAM` or `SOCK_DGRAM`, and `IPPROTO_TCP` or `IPPROTO_UDP`.
    let family, type, proto: Int32
    let hostname: String?
    /// The URL with its path (``FlowURL``).
    let url: String?
    let firstPartySite: String?
    let direction: FlowDirection?
    /// When the socket was made, in nanoseconds since 1970.
    let start: Int64
    /// When the flow was seen to connect, for an opened flow, or to close.
    let time: FlowTime
    /// The kernel's byte totals, for a closed flow whose final counts came.
    let bytesIn, bytesOut: UInt64?
}


/// An address and port, as a flow's record writes `remote_endpoint` and `local_endpoint`.
public struct FlowEndpoint: Codable, Hashable, Sendable {
    public let address: String
    public let port: Int
}


/// Which side opened a flow, as the kernel says from Darwin 23.
public enum FlowDirection: String, Codable, CaseIterable, Sendable {
    case inbound, outbound
}


/// A moment on both of the clocks a record needs.
struct FlowTime: Equatable, Sendable {
    /// On Endpoint Security's clock, `mach_absolute_time`.
    let machTime: Int64
    /// In nanoseconds since 1970.
    let wall: Int64
}


/// Takes the client's records, on its delivery queue.
protocol FlowConsumer: AnyObject {
    /// - Parameter record: A flow that opened or closed.
    func handle(_ record: FlowRecord)
}


// MARK: - The clocks
/// The three clocks, read together once per read, to turn a descriptor's `mach_continuous_time` ticks into a
/// record's times. Every sum is `Int64`, so no tick count, however odd, can trap.
struct FlowClock: Sendable {
    /// `mach_continuous_time`, `mach_absolute_time`, and the wall clock in nanoseconds since 1970.
    let continuous, absolute, wall: Int64
    /// The timebase. Nanoseconds are ticks times `numer` over `denom`.
    let numer, denom: Int64

    /// The clocks now.
    ///
    /// - Returns: The clocks.
    static func now() -> FlowClock {
        var base = mach_timebase_info_data_t()
        mach_timebase_info(&base)
        var wall = timespec()
        clock_gettime(CLOCK_REALTIME, &wall)
        // Absolute first, so the sleep between the two is never read as negative.
        let absolute = Int64(clamping: mach_absolute_time())
        return FlowClock(continuous: Int64(clamping: mach_continuous_time()), absolute: absolute,
                         wall: Int64(wall.tv_sec) * 1_000_000_000 + Int64(wall.tv_nsec), numer: Int64(base.numer),
                         denom: Int64(max(base.denom, 1)))
    }

    /// The times of a tick count. Ticks from before more sleep than the Mac had uptime give `machTime` 0.
    ///
    /// - Parameter ticks: `mach_continuous_time` ticks, or 0 for the clocks' own moment.
    /// - Returns: The times.
    func time(ofTicks ticks: UInt64) -> FlowTime {
        let ticks = ticks == 0 ? continuous : Int64(clamping: ticks)
        return FlowTime(machTime: max(0, ticks - (continuous - absolute)), wall: wall(ofTicks: ticks))
    }

    /// - Parameter ticks: `mach_continuous_time` ticks.
    /// - Returns: Their wall time, in nanoseconds since 1970.
    func wall(ofTicks ticks: Int64) -> Int64 {
        let bound = Int64.max / max(numer, 1)
        return wall &+ min(max(ticks - continuous, -bound), bound) * numer / denom
    }

    /// The clocks' moment in seconds of uptime, sleep included, for timing the client's own work.
    var seconds: TimeInterval {
        Double(continuous) * Double(numer) / Double(denom) / 1e9
    }
}
