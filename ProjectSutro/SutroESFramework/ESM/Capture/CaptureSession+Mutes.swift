//
//  CaptureSession+Mutes.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


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
    /// - Returns: `true` if every client accepted every call. Refusals are logged; ``appliedMutes`` becomes `list`
    ///   either way, so the next change is worked out from what was asked. `false` after ``stop()``, with nothing
    ///   sent.
    @discardableResult
    public func applyMutes(_ list: MuteList) -> Bool {
        guard !isStopped else { return false }
        let changes = appliedMutes.changes(to: list)
        appliedMutes = list
        return Self.apply(changes, on: lanes, label: label)
    }
    
    /// Mute this process on every lane's client, as eslogger mutes itself.
    ///
    /// - Parameters:
    ///   - lanes: The lanes, each with its client.
    ///   - label: Names the session in the log.
    static func muteSelf(on lanes: [CaptureLane], label: String) {
        let token = audit_token_t.currentProcess
        for lane in lanes where lane.client?.muteProcess(token) != true {
            logger.fault("""
                \(label, privacy: .public): couldn't mute this process on the \
                \(lane.eventClass.rawValue, privacy: .public) client, so its own activity will be captured.
                """)
        }
    }
    
    /// Make path mute calls on every lane's client, lane by lane. A refusal is logged and the rest still apply.
    ///
    /// - Parameters:
    ///   - changes: The calls, in order.
    ///   - lanes: The lanes.
    ///   - label: Names the session in the log, which counts each client's refusals.
    /// - Returns: `true` if every client accepted every call.
    @discardableResult
    static func apply(_ changes: [MuteChange], on lanes: [CaptureLane], label: String) -> Bool {
        guard !changes.isEmpty else { return true }
        var accepted = true
        for lane in lanes {
            let refused = changes.filter { lane.client?.setPathMute($0.mute, muted: $0.muted) != true }
            guard let first = refused.first else { continue }
            accepted = false
            logger.error("""
                \(label, privacy: .public): the \(lane.eventClass.rawValue, privacy: .public) client refused \
                \(refused.count) of \(changes.count) path mute changes, such as \
                \(first.muted ? "muting" : "unmuting", privacy: .public) \(first.mute.path).
                """)
        }
        return accepted
    }
}
