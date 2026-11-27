//
//  FlowSourceTable+Flows.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Flows
extension FlowSourceTable {
    /// A pending source became a flow. Record its opening, unless it's adopted or skipped.
    ///
    /// - Parameters:
    ///   - source: The source.
    ///   - ticks: When, from the update that made it a flow.
    ///   - first: Was that its first update? A source made before the client started is adopted only then.
    func open(_ source: inout FlowSource, at ticks: UInt64, first: Bool) {
        source.identifier = source.identifier ?? UUID.buffered()
        if source.isLoopback {
            source.stage = .skipped
            counts.loopback += 1
        } else if source.isExisting, first {
            source.stage = .adopted
        } else if !admit() {
            source.stage = .skipped
            counts.overBudget += 1
        } else {
            source.stage = .open
            emit(record(.opened, source, at: ticks))
        }
    }

    /// Record a flow's close, if its opening was recorded or it was adopted.
    ///
    /// - Parameters:
    ///   - source: The source, removed.
    ///   - wentLocal: Did the filter hold back its closing update, since it went through loopback after it opened?
    ///     Then it closes without counts, and it's counted as loopback, not as a loss.
    func close(_ source: FlowSource, wentLocal: Bool = false) {
        guard source.stage == .open || source.stage == .adopted else { return }
        if wentLocal {
            counts.loopback += 1
        } else if source.closedAt == nil {
            counts.closedWithoutCounts += 1
        }
        emit(record(.closed, source, at: source.closedAt ?? 0))
    }

    /// Is there room in this second's budget for one more flow to open? Adopted flows' closes aren't counted.
    ///
    /// - Returns: Whether there is, counting it.
    private func admit() -> Bool {
        if clock.seconds - window.start >= 1 { window = (clock.seconds, 0) }
        window.opened += 1
        return window.opened <= Self.budget
    }

    /// A record of a flow. Times are kept from going back, so a sequence of network steps sees them in order.
    ///
    /// - Parameters:
    ///   - kind: Opened or closed.
    ///   - source: The flow's source.
    ///   - ticks: When, or 0 for the moment the client read it.
    /// - Returns: The record.
    private func record(_ kind: FlowRecord.Kind, _ source: FlowSource, at ticks: UInt64) -> FlowRecord {
        let time = clock.time(ofTicks: ticks)
        if time.machTime >= lastTime.machTime { lastTime = time }
        let isTCP = source.provider == .tcpKernel || source.provider == .tcpUserland
        let process = source.details?.process ?? FlowProcess(pid: 0, name: "", state: .reaped)
        let items = source.details?.items ?? FlowItems()
        let counted = kind == .closed && source.closedAt != nil
        return FlowRecord(kind: kind, identifier: source.identifier ?? UUID.buffered(), process: process,
                          sourceApp: source.details?.sourceApp, isOwn: process.pid == Self.ownPID,
                          local: source.local.endpoint(),
                          remote: source.remote.endpoint() ?? FlowEndpoint(address: "", port: 0),
                          family: Int32(source.remote.family), type: isTCP ? SOCK_STREAM : SOCK_DGRAM,
                          proto: isTCP ? IPPROTO_TCP : IPPROTO_UDP, hostname: items.hostname, url: items.url,
                          firstPartySite: items.firstPartySite,
                          direction: source.direction, start: clock.wall(ofTicks: Int64(clamping: source.start)),
                          time: lastTime, bytesIn: counted ? source.received : nil,
                          bytesOut: counted ? source.sent : nil)
    }
}
