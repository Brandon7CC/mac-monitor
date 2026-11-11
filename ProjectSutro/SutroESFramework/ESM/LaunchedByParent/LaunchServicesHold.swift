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
/// Holds an app's exec until Launch Services says who launched it, usually within 250 ms.
///
/// Events behind a held exec wait so the lane stays in Endpoint Security's order. A lookup that takes longer than
/// ``maxWait`` is given up, so a stuck Launch Services read never stops the lane. An exec whose launched-by parent
/// Launch Services changes is stamped again with the indicators it was admitted with, when a rule reads that parent
/// (``CompiledIndicators/readsLaunchedByParent``), so its verdicts are the ones its record would give.
final class LaunchServicesHold {
    /// The most execs held at a time
    static let defaultMaxHeld = 64
    /// The longest an exec is held. Twice the upgrader's last read.
    static let defaultMaxWait: TimeInterval = 0.5
    static let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension",
                               category: "LaunchServicesHold")

    /// An exec waiting on its lookup
    private final class Held {
        var message: Message
        /// The set the exec was stamped with.
        let indicators: CompiledIndicators?
        var isSettled = false

        init(_ message: Message, indicators: CompiledIndicators?) {
            self.message = message
            self.indicators = indicators
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
    let maxWait: TimeInterval
    private let upgrader: LaunchedByParentUpgrader
    private let emit: (CapturedEvent) -> Void
    private let state = OSAllocatedUnfairLock(uncheckedState: State())
    /// Only used under ``state``'s lock
    private let encoder = StreamingJSONEncoder()
    /// The values a settled exec is stamped again with. Only used under ``state``'s lock.
    private var values = MessageValueCache()

    /// - Parameters:
    ///   - eventClass: The lane's event class.
    ///   - upgrader: Looks up each held exec.
    ///   - maxHeld: The most execs held at a time.
    ///   - maxWait: The longest an exec is held.
    ///   - emit: Called in order, under the hold's lock.
    init(eventClass: EventClass, upgrader: LaunchedByParentUpgrader, maxHeld: Int = LaunchServicesHold.defaultMaxHeld,
         maxWait: TimeInterval = LaunchServicesHold.defaultMaxWait, emit: @escaping (CapturedEvent) -> Void) {
        self.eventClass = eventClass
        self.maxHeld = maxHeld
        self.maxWait = maxWait
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
    /// - Parameters:
    ///   - message: An exec ``holds(_:)`` accepted.
    ///   - indicators: The set it was stamped with, to stamp it again when Launch Services changes its parent.
    func hold(_ message: Message, stampedWith indicators: CompiledIndicators? = nil) {
        guard case .exec(let exec) = message.event, let answer = exec.launched_by_parent,
              let target = exec.target.audit_token else { return submitEncoded(message) }
        let held = Held(message, indicators: indicators)
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
        // Not on the upgrader's queue, which a stuck read would block.
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + maxWait) { [weak self] in
            self?.settle(held, with: nil)
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

    /// Finish a lookup and send whatever is ready. Only the first call for an exec counts.
    ///
    /// - Parameters:
    ///   - held: The exec.
    ///   - better: Launch Services' answer, or `nil` to keep the current one.
    private func settle(_ held: Held, with better: LaunchedByParent?) {
        state.withLockUnchecked { state in
            guard !state.isClosed, !held.isSettled else { return }
            if let better { upgrade(held, to: better) }
            held.isSettled = true
            release(&state)
        }
    }

    /// Give an exec Launch Services' answer, and stamp it again when a rule reads its launched-by parent. Call under
    /// the lock.
    ///
    /// - Parameters:
    ///   - held: The exec.
    ///   - better: Launch Services' answer.
    private func upgrade(_ held: Held, to better: LaunchedByParent) {
        held.message.setLaunchedByParent(better)
        guard let indicators = held.indicators, indicators.readsLaunchedByParent else { return }
        indicators.stamp(&held.message, values: &values)
    }

    /// Send from the front of the line up to the first exec still held. Call under the lock.
    ///
    /// The sent slots are removed together at the end, so a long line isn't shifted once per slot.
    ///
    /// - Parameter state: The line.
    private func release(_ state: inout State) {
        var sent = 0
        walk: while sent < state.line.count {
            switch state.line[sent] {
            case .ready(let event):
                emit(event)
            case .held(let held):
                guard held.isSettled else { break walk }
                state.held -= 1
                if let event = encoded(held.message) { emit(event) }
            }
            sent += 1
        }
        state.line.removeFirst(sent)
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
