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
/// Holds an app's exec until Launch Services says who launched it (at most 250 ms).
///
/// Events behind a held exec wait so the lane stays in Endpoint Security's order.
final class LaunchServicesHold {
    /// The most execs held at a time
    static let defaultMaxHeld = 64
    static let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension",
                               category: "LaunchServicesHold")

    /// An exec waiting on its lookup
    private final class Held {
        var message: Message
        var isSettled = false

        init(_ message: Message) {
            self.message = message
        }
    }

    /// An event waiting in line
    private enum Slot {
        case ready(CapturedEvent)
        case held(Held)
    }

    /// Only touched under ``state``'s lock
    private struct State {
        /// Waiting events, oldest first
        var line: [Slot] = []
        /// Execs held right now
        var held = 0
        var isClosed = false
    }

    let eventClass: EventClass
    let maxHeld: Int
    private let upgrader: LaunchedByParentUpgrader
    private let emit: (CapturedEvent) -> Void
    private let state = OSAllocatedUnfairLock(uncheckedState: State())
    /// Only used under ``state``'s lock
    private let encoder = StreamingJSONEncoder()

    /// - Parameters:
    ///   - eventClass: The lane's event class.
    ///   - upgrader: Looks up each held exec.
    ///   - maxHeld: The most execs held at a time.
    ///   - emit: Called in order, under the hold's lock.
    init(eventClass: EventClass, upgrader: LaunchedByParentUpgrader, maxHeld: Int = LaunchServicesHold.defaultMaxHeld,
         emit: @escaping (CapturedEvent) -> Void) {
        self.eventClass = eventClass
        self.maxHeld = maxHeld
        self.upgrader = upgrader
        self.emit = emit
    }

    /// Should this event be held? Only an app's exec with a target audit token.
    ///
    /// - Parameter message: The event.
    /// - Returns: `true` to pass it to ``hold(_:)``.
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
    /// - Parameter message: An exec ``holds(_:)`` accepted.
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
        // Too many waiting: send it with the answer it has.
        guard accepted else { return submitEncoded(message) }
        upgrader.lookUp(answer, of: target) { [weak self] better in
            self?.settle(held, with: better)
        }
    }

    /// Send everything in line and stop. Lookups still running are ignored.
    func close() {
        state.withLockUnchecked { state in
            guard !state.isClosed else { return }
            for case .held(let held) in state.line { held.isSettled = true }
            release(&state)
            state.isClosed = true
        }
    }

    /// Finish a lookup and send whatever is ready.
    ///
    /// - Parameters:
    ///   - held: The exec.
    ///   - better: Launch Services' answer, or `nil` to keep the current one.
    private func settle(_ held: Held, with better: LaunchedByParent?) {
        state.withLockUnchecked { state in
            guard !state.isClosed else { return }
            if let better { held.message.setLaunchedByParent(better) }
            held.isSettled = true
            release(&state)
        }
    }

    /// Send from the front of the line up to the first exec still held. Call under the lock.
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

    /// Send an exec as it is, keeping its place in line.
    ///
    /// - Parameter message: The exec.
    private func submitEncoded(_ message: Message) {
        state.withLockUnchecked { state in
            guard !state.isClosed, let event = encoded(message) else { return }
            if state.line.isEmpty { emit(event) } else { state.line.append(.ready(event)) }
        }
    }

    /// Encode an exec. Call under the lock.
    ///
    /// - Parameter message: The exec.
    /// - Returns: The event, or `nil` if it couldn't be encoded.
    private func encoded(_ message: Message) -> CapturedEvent? {
        guard let json = try? encoder.encode(message) else {
            Self.logger.fault("Couldn't encode a held exec, so it was dropped.")
            return nil
        }
        return CapturedEvent(json: json, eventClass: eventClass)
    }
}
