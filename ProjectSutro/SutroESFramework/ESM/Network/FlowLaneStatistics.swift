//
//  FlowLaneStatistics.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Statistics
/// A network lane's lifetime counters (``FlowLane``). None of them is Endpoint Security's.
public struct FlowLaneStatistics: Equatable, Sendable {
    /// Flow records the client handed the lane.
    public var records: UInt64 = 0
    /// Records skipped while not recording, and those a mute covered.
    public var skipped: UInt64 = 0, muted: UInt64 = 0
    /// Records whose event couldn't be encoded.
    public var serializationFailures: UInt64 = 0
    /// Events that matched more indicators than a record lists, and records that list undetermined indicators.
    public var hitCappedEvents: UInt64 = 0, undeterminedEvents: UInt64 = 0
    /// Sockets the kernel couldn't tell the client of while the lane was registered (``FlowCounts/socketsLost``).
    public var socketsLost = 0
    /// Flows that closed without their final counts while the lane was registered.
    public var closedWithoutCounts = 0
    /// Flows past the rate budget while the lane was registered.
    public var overBudget = 0
}
