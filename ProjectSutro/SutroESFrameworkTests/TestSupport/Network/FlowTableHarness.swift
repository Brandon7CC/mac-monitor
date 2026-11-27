//
//  FlowTableHarness.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - A source table under test
/// A source table fed built messages, with fake process reads, a clock the test sets, and the records and queries it
/// gives out. Ticks are nanoseconds: the clock is 10 s up, 1 s of it asleep.
final class FlowTableHarness {
    /// What a built message's descriptor holds.
    typealias Descriptor = NStatMessageBuilder.Descriptor

    let build: NStatMessageBuilder
    let reads = FakeFlowReads()
    var records: [FlowRecord] = []
    var queries: [NStat.Request] = []
    /// Does a query's send work?
    var sends = true
    let darwin: Int
    private(set) var table: FlowSourceTable!

    /// When the clock was sampled, in ticks, and the wall time then.
    static let now: UInt64 = 10_000_000_000, wall: Int64 = 1_764_000_000_000_000_000

    /// - Parameters:
    ///   - darwin: The Darwin version to build and read for.
    ///   - previous: The table of a socket this one replaces.
    init(darwin: Int = 27, replacing previous: FlowTableHarness? = nil) {
        (self.darwin, build) = (darwin, NStatMessageBuilder(darwin: darwin))
        reads.processes = [100: FakeFlowReads.Process(upid: 5_000, pidversion: 7, path: "/usr/bin/nscurl")]
        table = FlowSourceTable(clock: Self.clock(), resolver: FlowProcessResolver(reads: reads.reads),
                                fallback: { _ in nil }, replacing: previous?.table,
                                query: { [unowned self] in queries.append($0); return sends },
                                emit: { [unowned self] in records.append($0) })
    }

    /// The clock, a number of seconds after it started.
    ///
    /// - Parameter later: Seconds later.
    /// - Returns: The clock.
    static func clock(_ later: Double = 0) -> FlowClock {
        let ticks = Int64(now) + Int64(later * 1e9)
        return FlowClock(continuous: ticks, absolute: ticks - 1_000_000_000, wall: wall + Int64(later * 1e9),
                         numer: 1, denom: 1)
    }

    /// Feed messages to the table.
    ///
    /// - Parameter messages: Each message, or several in one datagram.
    func feed(_ messages: [UInt8]...) {
        for message in messages {
            _ = message.withUnsafeBytes { NStat.forEachMessage(in: $0, table.handle) }
        }
    }

    /// Move the table's clock.
    ///
    /// - Parameter later: Seconds after the start.
    func at(_ later: Double) {
        table.clock = Self.clock(later)
    }

    /// pid 100's descriptor of a socket made after the clock was sampled, connected to Wikipedia.
    ///
    /// - Parameters:
    ///   - start: When the socket was made, in ticks after the sample.
    ///   - timestamp: When the descriptor was copied, in ticks after the sample.
    ///   - remote: Its remote end.
    ///   - local: Its local end.
    /// - Returns: The descriptor.
    func descriptor(start: Int64 = 100, timestamp: Int64 = 200,
                    remote: NStatMessageBuilder.Endpoint? = .init(address: "198.35.26.224", port: 443),
                    local: NStatMessageBuilder.Endpoint? = .init(address: "192.168.64.2", port: 49_310)) -> Descriptor {
        Descriptor(upid: 5_000, start: UInt64(Int64(Self.now) + start), timestamp: UInt64(Int64(Self.now) + timestamp),
                   pid: 100, local: local, remote: remote, name: "nscurl", state: 4, ifnetProperties: 0x0800_0010)
    }
}
