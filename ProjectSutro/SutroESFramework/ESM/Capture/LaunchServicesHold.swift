//
//  LaunchServicesHold.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/6/26.
//

import Foundation
import OSLog
import os


// MARK: - Launch Services hold
/// Holds an app's exec until Launch Services tells us who launched it.
///
/// Apps that Launch Services starts are `application.…` launchd jobs, so the exec alone only names launchd. We hold
/// the exec while ``LaunchedByParentUpgrader`` reads the app's record, which usually takes 50 ms and never more than
/// 250 ms. Mac Monitor and every `macmonitor` stream then receive the exec once, with the real launcher.
///
/// Events the lane handles in the meantime wait in line behind the exec. That keeps the lane in Endpoint Security's
/// order, so `global_seq_num` never goes backwards and a held exec never looks like a drop. Other lanes don't wait.
///
/// **Limits:**
///   - At most ``maxHeld`` execs are held at a time. Past that, an exec goes out with the answer it already has.
///   - ``close()`` sends every held exec right away.
///
/// ``submit(_:)`` and ``hold(_:)`` run on the lane's handler queue and lookups finish on the upgrader's queue. Both
/// emit under the hold's lock, so events always leave in order.
final class LaunchServicesHold {
    /// The most execs we hold at a time
    static let defaultMaxHeld = 64
    static let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension",
                               category: "LaunchServicesHold")

    /// An exec waiting for its lookup.
    private final class Held {
        /// The exec
        var message: Message
        /// Has the lookup finished?
        var isSettled = false

        /// - Parameter message: The exec.
        init(_ message: Message) {
            self.message = message
        }
    }

    /// One event waiting in line
    private enum Slot {
        /// An event that's ready to send
        case ready(CapturedEvent)
        /// An exec that's ready once its lookup finishes
        case held(Held)
    }

    /// The line of waiting events. Only touched under ``state``'s lock.
    private struct State {
        /// Waiting events, oldest first. Empty when nothing is held.
        var line: [Slot] = []
        /// How many execs are held
        var held = 0
        /// Once closed we never emit again.
        var isClosed = false
    }

    /// The lane's event class
    let eventClass: EventClass
    /// The most execs held at a time
    let maxHeld: Int
    private let upgrader: LaunchedByParentUpgrader
    private let emit: (CapturedEvent) -> Void
    private let state = OSAllocatedUnfairLock(uncheckedState: State())
    /// Encodes held execs. Only used under ``state``'s lock.
    private let encoder = StreamingJSONEncoder()

    /// - Parameters:
    ///   - eventClass: The lane's event class.
    ///   - upgrader: Looks up each held exec.
    ///   - maxHeld: The most execs held at a time.
    ///   - emit: Receives each event in order. It's called under the hold's lock, so it must not block.
    init(eventClass: EventClass, upgrader: LaunchedByParentUpgrader, maxHeld: Int = LaunchServicesHold.defaultMaxHeld,
         emit: @escaping (CapturedEvent) -> Void) {
        self.eventClass = eventClass
        self.maxHeld = maxHeld
        self.upgrader = upgrader
        self.emit = emit
    }

    /// Should we hold this event?
    ///
    /// Only an app's exec is held, and only when it has a target audit token to match the record against.
    ///
    /// - Parameter message: The event.
    /// - Returns: `true` if it should go to ``hold(_:)``.
    static func holds(_ message: Message) -> Bool {
        guard case .exec(let exec) = message.event, let answer = exec.launched_by_parent else { return false }
        return answer.needsLaunchServices && exec.target.audit_token != nil
    }

    /// Send an event now, or queue it behind any held execs.
    ///
    /// - Parameter event: The event.
    func submit(_ event: CapturedEvent) {
        state.withLockUnchecked { state in
            guard !state.isClosed else { return }
            if state.line.isEmpty { emit(event) } else { state.line.append(.ready(event)) }
        }
    }

    /// Hold an exec until its lookup finishes.
    ///
    /// When ``maxHeld`` execs are already waiting, the exec goes in line with the answer it has.
    ///
    /// - Parameter message: An exec that ``holds(_:)`` accepted.
    func hold(_ message: Message) {
        guard case .exec(let exec) = message.event, let answer = exec.launched_by_parent,
              let target = exec.target.audit_token else { return submitEncoded(message) }
        let held = Held(message)
        let accepted = state.withLockUnchecked { state -> Bool in
            guard !state.isClosed, state.held < maxHeld else { return false }
            state.held += 1
            state.line.append(.held(held))
            return true
        }
        guard accepted else { return submitEncoded(message) }
        upgrader.lookUp(answer, of: target) { [weak self] better in
            self?.settle(held, with: better)
        }
    }

    /// Send everything in line, then stop.
    ///
    /// Held execs go out with the answer they have. Lookups that finish afterwards are ignored.
    func close() {
        state.withLockUnchecked { state in
            guard !state.isClosed else { return }
            for case .held(let held) in state.line { held.isSettled = true }
            release(&state)
            state.isClosed = true
        }
    }

    /// Finish a held exec's lookup and send whatever is now ready.
    ///
    /// - Parameters:
    ///   - held: The exec.
    ///   - better: Launch Services' answer, or `nil` to keep the one the exec has.
    private func settle(_ held: Held, with better: LaunchedByParent?) {
        state.withLockUnchecked { state in
            guard !state.isClosed else { return }
            if let better { held.message.setLaunchedByParent(better) }
            held.isSettled = true
            release(&state)
        }
    }

    /// Send events from the front of the line until we reach an exec that's still held. Call under the lock.
    ///
    /// - Parameter state: The line.
    private func release(_ state: inout State) {
        while let first = state.line.first {
            switch first {
            case .ready(let event):
                emit(event)
            case .held(let held):
                guard held.isSettled else { return }
                state.held -= 1
                if let event = encoded(held.message) { emit(event) }
            }
            state.line.removeFirst()
        }
    }

    /// Send an exec with the answer it already has, keeping its place in line.
    ///
    /// - Parameter message: The exec.
    private func submitEncoded(_ message: Message) {
        state.withLockUnchecked { state in
            guard !state.isClosed, let event = encoded(message) else { return }
            if state.line.isEmpty { emit(event) } else { state.line.append(.ready(event)) }
        }
    }

    /// Encode an exec the way the lane sends it. Call under the lock.
    ///
    /// - Parameter message: The exec.
    /// - Returns: The event, or `nil` if it couldn't be encoded. We log the failure.
    private func encoded(_ message: Message) -> CapturedEvent? {
        guard let json = try? encoder.encode(message) else {
            Self.logger.fault("Couldn't encode a held exec, so it was dropped.")
            return nil
        }
        return CapturedEvent(json: json, eventClass: eventClass)
    }
}
