//
//  CaptureSession+Mutes.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Path mutes
extension CaptureSession {
    /// Make every client's path mutes match `list`: mute what's new and unmute what's gone since ``appliedMutes``,
    /// one call per event (``MuteList/changes(to:)``), so each client ends up with `list` whichever client serves an
    /// event.
    ///
    /// Endpoint Security's own default mutes are left alone, except where one shares a path and type with a mute
    /// cleared for every event: `es_unmute_path` clears that key's events, Apple's included. Apple's defaults are AUTH
    /// events, which these clients never subscribe to. A call for a network flow event (``MacMonitorEvent``) isn't
    /// made: Endpoint Security refuses its type. The network lane applies `list`'s process mutes itself
    /// (``FlowMutes``).
    ///
    /// - Parameter list: The mutes every client should have, such as the saved mute set.
    /// - Returns: `true` if every client accepted every call. Refusals are logged. ``appliedMutes`` becomes `list`
    ///   either way, so the next change is worked out from what was asked. `false` after ``stop()``, with nothing
    ///   sent.
    @discardableResult
    public func applyMutes(_ list: MuteList) -> Bool {
        guard !isStopped else { return false }
        let changes = Self.endpointSecurityChanges(from: appliedMutes, to: list)
        appliedMutes = list
        flowLane?.setMutes(FlowMutes(list))
        /// `apply` first, so every lane gets the calls after one refuses.
        return lanes.reduce(true) { $1.apply(changes) && $0 }
    }

    /// The calls that move a client's path mutes from one list to another (``MuteList/changes(to:)``), without those
    /// for a network flow event (``MacMonitorEvent``). Endpoint Security refuses a flow event's type.
    ///
    /// - Parameters:
    ///   - list: The mutes the clients have.
    ///   - target: The mutes they should have.
    /// - Returns: The calls, in order.
    static func endpointSecurityChanges(from list: MuteList, to target: MuteList) -> [MuteChange] {
        list.changes(to: target).filter { $0.mute.events.allSatisfy { MacMonitorEvent($0) == nil } }
    }
}
