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
    /// events, which these clients never subscribe to.
    ///
    /// - Parameter list: The mutes every client should have, such as the saved mute set.
    /// - Returns: `true` if every client accepted every call. Refusals are logged. ``appliedMutes`` becomes `list`
    ///   either way, so the next change is worked out from what was asked. `false` after ``stop()``, with nothing
    ///   sent.
    @discardableResult
    public func applyMutes(_ list: MuteList) -> Bool {
        guard !isStopped else { return false }
        let changes = appliedMutes.changes(to: list)
        appliedMutes = list
        /// `apply` first, so every lane gets the calls after one refuses.
        return lanes.reduce(true) { $1.apply(changes) && $0 }
    }
}
