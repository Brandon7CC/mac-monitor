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
/// Launch Services changes is stamped again with the indicators it was admitted with, when a rule or sequence reads
/// that parent (``CompiledIndicators/readsLaunchedByParent``), so its verdicts are the ones its record would give.
///
/// **Sequences:** the lane's events advance their sequences as they're sent, not as they're built
/// (``CompiledIndicators/advance(_:steps:values:)``): a held exec with the launched-by parent it leaves with, and the
/// events behind it after it, so the steps keep Endpoint Security's order. An event that matched a step waits in line
/// unencoded, and is encoded once it has advanced them, with the hits of the chains it completed.
final class LaunchServicesHold {
    /// The most execs held at a time
    static let defaultMaxHeld = 64
    /// The longest an exec is held. Twice the upgrader's last read.
    static let defaultMaxWait: TimeInterval = 0.5
    static let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension",
                               category: "LaunchServicesHold")

    /// An event stamped and not yet sent, whose sequence steps advance when it's sent.
    private struct Stamped {
        var message: Message
        /// The set it was stamped with.
        let indicators: CompiledIndicators?
        /// The session's chains for the set's sequences, or `nil` for the set's own.
        let chains: SessionChains?
        /// The sequence steps it matched.
        var steps: ContiguousArray<Int32>
    }

    /// An exec waiting on its lookup
    private final class Held {
        var event: Stamped
        var isSettled = false
        /// Did Launch Services give it a launched-by parent?
        var isUpgraded = false

        init(_ event: Stamped) {
            self.event = event
        }
    }

    /// An event waiting in line
    private enum Slot {
        case ready(CapturedEvent)
        /// An event that matched a sequence step, not encoded yet, boxed so a slot stays small
        indirect case stamped(Stamped)
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
    /// The values events are stamped again and advance their sequences with. Only used under ``state``'s lock.
    private var values = MessageValueCache()
    /// The lineage table, which is told who launched an app once Launch Services says.
    private let lineage: ProcessLineage?

    /// - Parameters:
    ///   - eventClass: The lane's event class.
    ///   - upgrader: Looks up each held exec.
    ///   - maxHeld: The most execs held at a time.
    ///   - maxWait: The longest an exec is held.
    ///   - lineage: The table an indicator's ancestor fields are read from as an exec is stamped again.
    ///   - emit: Called in order, under the hold's lock.
    init(eventClass: EventClass, upgrader: LaunchedByParentUpgrader, maxHeld: Int = LaunchServicesHold.defaultMaxHeld,
         maxWait: TimeInterval = LaunchServicesHold.defaultMaxWait, lineage: ProcessLineage? = nil,
         emit: @escaping (CapturedEvent) -> Void) {
        values.lineage = lineage
        self.lineage = lineage
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

    /// Send an event that matched sequence steps now, or queue it behind any held execs, and advance its sequences
    /// as it's sent.
    ///
    /// - Parameters:
    ///   - message: The event, stamped deferring its steps
    ///     (``CompiledIndicators/stamp(_:values:chains:deferringSteps:)``).
    ///   - indicators: The set it was stamped with.
    ///   - chains: The session's chains for the set's sequences, or `nil` for the set's own.
    ///   - steps: The steps that stamp handed back.
    func submit(_ message: Message, stampedWith indicators: CompiledIndicators?, chains: SessionChains?,
                steps: ContiguousArray<Int32>) {
        submit(Stamped(message: message, indicators: indicators, chains: chains, steps: steps))
    }

    /// Hold an exec until its lookup finishes.
    ///
    /// - Parameters:
    ///   - message: An exec ``holds(_:)`` accepted.
    ///   - indicators: The set it was stamped with, to stamp it again when Launch Services changes its parent, and
    ///     to advance its sequences with as it's sent.
    ///   - chains: The session's chains for the set's sequences, or `nil` for the set's own.
    ///   - steps: The sequence steps its stamp deferred.
    func hold(_ message: Message, stampedWith indicators: CompiledIndicators? = nil, chains: SessionChains?,
              steps: ContiguousArray<Int32> = []) {
        let event = Stamped(message: message, indicators: indicators, chains: chains, steps: steps)
        guard case .exec(let exec) = message.event, let answer = exec.launched_by_parent,
              let target = exec.target.audit_token else { return submit(event) }
        let held = Held(event)
        let accepted = state.withLockUnchecked { state -> Bool in
            guard !state.isClosed, state.held < maxHeld else { return false }
            state.held += 1
            state.line.append(.held(held))
            return true
        }
        // Too many waiting: send it with the answer it has.
        guard accepted else { return submit(event) }
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
            if let better {
                held.event.message.setLaunchedByParent(better)
                held.isUpgraded = true
                if case .exec(let exec) = held.event.message.event, let target = exec.target.audit_token {
                    lineage?.setLauncher(ProcessLineage.launcher(better), of: ProcessKey(target))
                }
            }
            held.isSettled = true
            release(&state)
        }
    }

    /// Stamp a settled exec again, with its rules and its sequence steps, when Launch Services gave it a launched-by
    /// parent and the set reads one. Call under the lock, as it's sent.
    ///
    /// - Parameter held: The exec.
    /// - Returns: It, as it's sent.
    private func restamped(_ held: Held) -> Stamped {
        var event = held.event
        guard held.isUpgraded, let indicators = event.indicators, indicators.readsLaunchedByParent else { return event }
        event.steps = indicators.stamp(&event.message, values: &values, chains: event.chains, deferringSteps: true)
        return event
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
            case .stamped(let event):
                send(event)
            case .held(let held):
                guard held.isSettled else { break walk }
                state.held -= 1
                send(restamped(held))
            }
            sent += 1
        }
        state.line.removeFirst(sent)
    }

    /// Send a stamped event now, or queue it behind any held execs.
    ///
    /// - Parameter event: The event.
    private func submit(_ event: Stamped) {
        state.withLockUnchecked { state in
            guard !state.isClosed else { return }
            if state.line.isEmpty { send(event) } else { state.line.append(.stamped(event)) }
        }
    }

    /// Advance a stamped event's sequences, then encode and emit it. Call under the lock, in the line's order.
    ///
    /// - Parameter event: The event.
    private func send(_ event: Stamped) {
        var message = event.message
        event.indicators?.advance(&message, steps: event.steps, values: &values, chains: event.chains)
        guard let json = try? encoder.encode(message) else {
            return Self.logger.fault("Couldn't encode an event the exec lane held, so it was dropped.")
        }
        emit(CapturedEvent(json: json, eventClass: eventClass))
    }
}
