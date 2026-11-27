//
//  FlowClientStatus.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - The client's status
/// How the network statistics client is doing (``NetworkStatisticsClient``). It says whether its socket is open, how
/// full its buffer got, and what it couldn't report.
public struct FlowClientStatus: Codable, Equatable, Sendable {
    /// Whether the client's socket is open.
    public enum State: String, Codable, Sendable {
        /// No consumer, so no socket.
        case off
        case on
        /// The socket couldn't be opened (``reason``).
        case unavailable
    }

    public var state = State.off
    /// Why the socket couldn't be opened.
    public var reason: String?
    /// The receive buffer the kernel gave, in bytes. It's 4 MB unless the kernel refused that.
    public var receiveBuffer = 0
    /// The most bytes seen waiting at the start of a read.
    public var bufferHighWater = 0
    /// The providers the client can't read, by name, and why.
    public var providersOff: [String: String] = [:]
    /// The sources the kernel reports now, and how many of them are open or adopted flows.
    public var openSources = 0, flows = 0
    public var counts = FlowCounts()

    /// The status of a client with no socket.
    public init() {}
}


/// What the client couldn't report, or chose not to, since its socket opened.
public struct FlowCounts: Codable, Equatable, Sendable {
    /// Sockets whose add the kernel couldn't queue, counted by the jumps in source references.
    public var lostSources = 0
    /// Queries whose reply the kernel couldn't queue.
    public var queryFailures = 0
    /// Flows that closed without their final counts.
    public var closedWithoutCounts = 0
    /// Sources removed after a message to the client was dropped.
    public var closedAfterDrop = 0
    /// Flows that closed while the client reopened its socket, whose close is lost.
    public var closedDuringReopen = 0
    /// Sources whose first message wasn't their add.
    public var lateSources = 0
    /// Adds another client of the kernel couldn't queue, which on macOS 13 and 14 hide sockets from Mac Monitor too.
    public var otherClientFailures = 0
    /// How many times the client reopened its socket to be offered sockets first.
    public var reopens = 0
    /// Local connections the client skipped, which aren't recorded. The kernel holds back most loopback sources'
    /// updates, and those sources aren't counted here. They still count in ``FlowClientStatus/openSources`` until
    /// they're removed. This counts the ones whose update still came, such as a UDP subflow, or a socket whose
    /// interface wasn't known yet when its update was sent. It also counts flows that went local after they opened,
    /// whose close is recorded without counts. Such a flow can still close early at a loss check, or be lost in a
    /// reopen, since the kernel no longer answers its queries.
    public var loopback = 0
    /// Flows past the rate budget, which aren't recorded.
    public var overBudget = 0
    /// Processes read while they were zombies, and reaped processes the lineage table didn't know either.
    public var zombies = 0, unresolved = 0
    /// Messages that couldn't be read, datagrams cut short, and adds past the table's capacity.
    public var malformed = 0, truncated = 0, ignoredSources = 0

    /// No counts yet.
    public init() {}

    /// Sockets the kernel couldn't tell the client of: adds it couldn't queue, and closes lost while the client
    /// reopened its socket.
    public var socketsLost: Int { lostSources + closedDuringReopen }
}
