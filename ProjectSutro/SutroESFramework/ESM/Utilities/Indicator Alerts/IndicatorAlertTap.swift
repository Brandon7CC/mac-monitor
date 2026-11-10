//
//  IndicatorAlertTap.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import os


// MARK: - The tap on received events
/// Where ``EndpointSecurityManager`` hands live events with indicator hits to notifications (agent context).
///
/// Candidates are picked as a batch arrives (``candidates(in:)``), after the platform-binary drop, so notifications
/// follow what the tables keep, and held until the batch is inserted (``hold(_:)``, ``takeHeld()``). Only those the
/// store kept are delivered (``deliver(_:kept:)``): an event recorded before a Clear, or while a trace is open, never
/// notifies, so a click always finds its event unless it was cleared since. Traces read from a file are inserted
/// another way and never reach it.
///
/// While nothing is configured to receive them, a batch costs one lock read.
///
/// **Threading:** thread-safe.
public final class IndicatorAlertTap: @unchecked Sendable {
    /// Takes the candidates of each inserted batch, on the store's queue.
    public typealias Deliver = @Sendable ([IndicatorAlertEvent]) -> Void

    /// What it's configured with, and the candidates waiting for their batch's insert.
    private struct State {
        var deliver: Deliver?
        var settings = IndicatorAlertSettings()
        var disabled: Set<UUID> = []
        var held: [IndicatorAlertEvent] = []
    }

    private let state = OSAllocatedUnfairLock(initialState: State())
    /// This app's user, whose processes notifications don't name by user.
    private let appUser = getuid()

    /// Picks nothing until ``configure(_:disabled:deliver:)``.
    public init() {}

    /// Notify for these settings from now on, or stop.
    ///
    /// - Parameters:
    ///   - settings: This user's notification settings.
    ///   - disabled: The indicators known to be off.
    ///   - deliver: Takes each inserted batch's candidates, or `nil` to pick none. It's dropped while every switch is
    ///     off.
    public func configure(_ settings: IndicatorAlertSettings, disabled: Set<UUID>, deliver: Deliver?) {
        state.withLock { state in
            state.deliver = settings.isOff ? nil : deliver
            (state.settings, state.disabled) = (settings, disabled)
            if state.deliver == nil { state.held = [] }
        }
    }

    /// The candidates in a batch (``IndicatorAlertPolicy``). Call it on the XPC queue, as the batch arrives.
    ///
    /// - Parameter messages: The batch's events the store will be given.
    /// - Returns: At most one per event, or none at once when nothing receives them.
    public func candidates(in messages: [Message]) -> [IndicatorAlertEvent] {
        let (deliver, settings, disabled) = state.withLock { ($0.deliver, $0.settings, $0.disabled) }
        guard deliver != nil else { return [] }
        return messages.compactMap {
            IndicatorAlertPolicy.pick($0, settings: settings, disabled: disabled, appUser: appUser)
        }
    }

    /// Hold candidates until their batch is inserted.
    ///
    /// - Parameter events: The candidates.
    public func hold(_ events: [IndicatorAlertEvent]) {
        state.withLock { state in
            guard state.deliver != nil else { return }
            state.held.append(contentsOf: events)
        }
    }

    /// - Returns: The candidates held, which their batch's insert delivers.
    public func takeHeld() -> [IndicatorAlertEvent] {
        state.withLock { state in
            defer { state.held = [] }
            return state.held
        }
    }

    /// Deliver the candidates whose events the store kept.
    ///
    /// - Parameters:
    ///   - events: The candidates of a batch.
    ///   - kept: The identities of those events the store kept.
    public func deliver(_ events: [IndicatorAlertEvent], kept: Set<UUID>) {
        guard !events.isEmpty, let deliver = state.withLock({ $0.deliver }) else { return }
        let delivered = events.filter { kept.contains($0.eventID) }
        if !delivered.isEmpty { deliver(delivered) }
    }
}
