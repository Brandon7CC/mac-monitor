//
//  EventHold.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/6/26.
//

import Foundation
import OSLog
import os


// MARK: - Holding events
/// Holds a lane's events that wait for an answer before they're sent, in Endpoint Security's order: an app's exec
/// until Launch Services says who launched it, usually within 250 ms, a written file's close until its scan with
/// Apple's XProtect rules is done (``FileScanner``), and an exec until the scan of the script it runs is. An app's exec
/// that runs a script waits for both.
///
/// Events behind a held one wait so the lane stays in Endpoint Security's order. An answer that takes longer than
/// ``maxWait`` is given up, so a stuck Launch Services read or a slow scan never stops the lane: an exec leaves with
/// the parent it has, and a close or exec with `yara_scan` saying the scanner was busy. A line that grows past
/// ``maxLine`` behind held events gives up on the oldest the same way. An event its answer changes is stamped again
/// with the indicators it was admitted with, when a rule or sequence reads what changed
/// (``CompiledIndicators/readsLaunchedByParent``, ``CompiledIndicators/readsYaraScan``), so its verdicts are the
/// ones its record would give.
///
/// **Places:** Launch Services holds and scan holds have places of their own (``maxHeld``, ``maxScanHeld``), so
/// execs held for their scripts never take the places app execs need. An event with no place for its scan leaves as
/// busy, and one with no place for Launch Services keeps the parent it has.
///
/// **Sequences:** the lane's events advance their sequences as they're sent, not as they're built
/// (``CompiledIndicators/advance(_:steps:values:)``): a held event with the answer it leaves with, and the events
/// behind it after it, so the steps keep Endpoint Security's order. An event that matched a step waits in line
/// unencoded, and is encoded once it has advanced them, with the hits of the chains it completed.
final class EventHold {
    /// The most events held at a time for Launch Services, and for their scans on the file lane.
    static let defaultMaxHeld = 64
    /// The most execs the process lane holds at a time for their scripts' scans. A held exec carries its arguments,
    /// environment and script text, up to a few MiB, so fewer are held than closes.
    static let execScanHolds = 16
    /// The longest an event is held. Twice the upgrader's last read.
    static let defaultMaxWait: TimeInterval = 0.5
    /// The most events waiting in line behind held ones: the file lane can take thousands a second.
    static let defaultMaxLine = 4096
    /// The QoS a held event is given up at: the handoff's (``EventHandoff/qos``), above the scanner's utility QoS, so
    /// the wait's cap holds on a busy Mac whose utility threads wait. The scans it caps stay at utility.
    static let giveUpQoS = EventHandoff.qos
    static let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension",
                               category: "EventHold")

    /// Only touched under ``state``'s lock
    private struct State {
        /// Waiting events, oldest first
        var line: [Slot] = []
        /// Events held for Launch Services right now
        var held = 0
        /// Events held for their scans right now
        var scanHeld = 0
        var isClosed = false
    }

    let eventClass: EventClass
    /// The most events held at a time for Launch Services.
    let maxHeld: Int
    /// The most events held at a time for their scans.
    let maxScanHeld: Int
    let maxWait: TimeInterval
    let maxLine: Int
    /// Looks up app execs' launched-by parents. Only the exec lane has one.
    private let upgrader: LaunchedByParentUpgrader?
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
    ///   - upgrader: Looks up each held exec, on the exec lane. `nil` on a lane that holds only scans.
    ///   - maxHeld: The most events held at a time for Launch Services.
    ///   - maxScanHeld: The most events held at a time for their scans.
    ///   - maxWait: The longest an event is held.
    ///   - maxLine: The most events waiting in line behind held ones.
    ///   - lineage: The table an indicator's ancestor fields are read from as an event is stamped again.
    ///   - emit: Called in order, under the hold's lock.
    init(eventClass: EventClass, upgrader: LaunchedByParentUpgrader?, maxHeld: Int = EventHold.defaultMaxHeld,
         maxScanHeld: Int = EventHold.defaultMaxHeld, maxWait: TimeInterval = EventHold.defaultMaxWait,
         maxLine: Int = EventHold.defaultMaxLine, lineage: ProcessLineage? = nil,
         emit: @escaping (CapturedEvent) -> Void) {
        values.lineage = lineage
        self.lineage = lineage
        self.eventClass = eventClass
        self.maxHeld = maxHeld
        self.maxScanHeld = maxScanHeld
        self.maxWait = maxWait
        self.maxLine = maxLine
        self.upgrader = upgrader
        self.emit = emit
    }

    /// Should this event be held for Launch Services? Only an app's exec with a target audit token.
    ///
    /// - Parameter message: The event.
    /// - Returns: `true` to pass it to ``hold(_:stampedWith:chains:steps:scan:)``.
    static func holds(_ message: Message) -> Bool {
        guard case .exec(let exec) = message.event, let answer = exec.launched_by_parent else { return false }
        return answer.needsLaunchServices && exec.target.audit_token != nil
    }

    /// Send an event now, or queue it behind any held events.
    ///
    /// - Parameter event: The event.
    func submit(_ event: CapturedEvent) {
        state.withLockUnchecked { state in
            guard !state.isClosed else { return }
            if state.line.isEmpty { return emit(event) }
            state.line.append(.ready(event))
            trim(&state)
        }
    }

    /// Send an event that matched sequence steps now, or queue it behind any held events, and advance its sequences
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

    /// Hold an event until its answers come: an app's exec (``holds(_:)``) until its Launch Services lookup finishes,
    /// on a lane with the upgrader, and a close, rename or exec until its scan is done, when it has a ticket.
    ///
    /// - Parameters:
    ///   - message: The event, stamped without its answers.
    ///   - indicators: The set it was stamped with, to stamp it again when an answer changes what the set reads,
    ///     and to advance its sequences with as it's sent.
    ///   - chains: The session's chains for the set's sequences, or `nil` for the set's own.
    ///   - steps: The sequence steps its stamp deferred.
    ///   - ticket: Where its scan's answer comes, or `nil` when no scan is queued for it.
    func hold(_ message: Message, stampedWith indicators: CompiledIndicators? = nil, chains: SessionChains?,
              steps: ContiguousArray<Int32> = [], scan ticket: FileScanTicket? = nil) {
        let event = Stamped(message: message, indicators: indicators, chains: chains, steps: steps)
        var lookup: (upgrader: LaunchedByParentUpgrader, answer: LaunchedByParent, target: AuditToken)?
        if let upgrader, Self.holds(message), case .exec(let exec) = message.event,
           let answer = exec.launched_by_parent, let target = exec.target.audit_token {
            lookup = (upgrader, answer, target)
        }
        var wanted = Set<Answer>()
        if lookup != nil { wanted.insert(.launchServices) }
        if ticket != nil { wanted.insert(.scan) }
        guard !wanted.isEmpty else { return submit(event) }
        guard let held = enqueue(event, wanting: wanted) else {
            var unheld = event
            if ticket != nil { Self.leaveBusy(&unheld.message) }
            return submit(unheld, restamping: ticket == nil ? nil : { $0.readsYaraScan })
        }
        if held.places.contains(.launchServices), let lookup {
            let lineage = lineage
            lookup.upgrader.lookUp(lookup.answer, of: lookup.target) { [weak self] better in
                self?.settle(held, .launchServices, with: better.map { better in { message in
                    message.setLaunchedByParent(better)
                    lineage?.setLauncher(ProcessLineage.launcher(better), of: ProcessKey(lookup.target))
                } })
            }
        }
        if held.places.contains(.scan), let ticket {
            ticket.whenAnswered { [weak self] scan in
                self?.settle(held, .scan, with: { message in message.setYaraScan(scan) })
            }
        }
        giveUp(on: held, after: maxWait)
    }

    /// Send everything in line and stop. Answers still to come are ignored, and an event still waiting leaves as it
    /// would if its wait ran out.
    func close() {
        state.withLockUnchecked { state in
            guard !state.isClosed else { return }
            for case .held(let held) in state.line where !held.isSettled { giveUp(held) }
            release(&state)
            state.isClosed = true
        }
    }

    /// Put an event in line as held, for the answers it has places for. A scan with no place leaves as busy.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - wanted: The answers it waits for.
    /// - Returns: The held event, or `nil` when there's no place for any of its answers. One that isn't held is sent
    ///   with the answers it has.
    private func enqueue(_ event: Stamped, wanting wanted: Set<Answer>) -> Held? {
        state.withLockUnchecked { state -> Held? in
            guard !state.isClosed else { return nil }
            var places = Set<Answer>()
            if wanted.contains(.launchServices), state.held < maxHeld { places.insert(.launchServices) }
            if wanted.contains(.scan), state.scanHeld < maxScanHeld { places.insert(.scan) }
            guard !places.isEmpty else { return nil }
            let held = Held(event, places: places, changes: wanted)
            if wanted.contains(.scan), !places.contains(.scan) {
                Self.leaveBusy(&held.event.message)
                held.isChanged = true
            }
            if places.contains(.launchServices) { state.held += 1 }
            if places.contains(.scan) { state.scanHeld += 1 }
            state.line.append(.held(held))
            return held
        }
    }

    /// Give up on an event's answers after a while, at ``giveUpQoS``. Not on an answer's own queue, which a stuck read
    /// or a long scan would block.
    ///
    /// - Parameters:
    ///   - held: The event.
    ///   - wait: How long.
    private func giveUp(on held: Held, after wait: TimeInterval) {
        DispatchQueue.global(qos: Self.giveUpQoS.qosClass).asyncAfter(deadline: .now() + wait, qos: Self.giveUpQoS,
                                                                     flags: .enforceQoS) { [weak self] in
            guard let self else { return }
            self.state.withLockUnchecked { state in
                guard !state.isClosed, !held.isSettled else { return }
                self.giveUp(held)
                self.release(&state)
            }
        }
    }

    /// Settle an event as its wait running out does: a scan still to come leaves as busy, and Launch Services'
    /// parent stays as it is. Call under the lock.
    ///
    /// - Parameter held: The event.
    private func giveUp(_ held: Held) {
        if held.awaits.contains(.scan) {
            Self.leaveBusy(&held.event.message)
            held.isChanged = true
        }
        held.awaits.removeAll()
    }

    /// Mark an event's scan as given up: the scanner couldn't answer in time.
    ///
    /// - Parameter message: The event.
    private static func leaveBusy(_ message: inout Message) {
        message.setYaraScan(.notScanned(YaraScan.busy))
    }

    /// Take one of an event's answers, and send whatever is ready once it has them all. Only the first of each
    /// counts.
    ///
    /// - Parameters:
    ///   - held: The event.
    ///   - answer: Which answer.
    ///   - change: What the answer changes, or `nil` to leave the event as it is.
    private func settle(_ held: Held, _ answer: Answer, with change: ((inout Message) -> Void)?) {
        state.withLockUnchecked { state in
            guard !state.isClosed, held.awaits.remove(answer) != nil else { return }
            if let change {
                change(&held.event.message)
                held.isChanged = true
            }
            if held.isSettled { release(&state) }
        }
    }

    /// Stamp an event again, with its rules and its sequence steps, when a set reads what changed. Call under the
    /// lock, as it's sent.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - reads: Does a set read what changed?
    /// - Returns: It, as it's sent.
    private func restamped(_ event: Stamped, reads: (CompiledIndicators) -> Bool) -> Stamped {
        var event = event
        guard let indicators = event.indicators, reads(indicators) else { return event }
        event.steps = indicators.stamp(&event.message, values: &values, chains: event.chains, deferringSteps: true)
        return event
    }

    /// When the line has grown past ``maxLine``, give up on the oldest events still held, until it's sent down to
    /// it. Call under the lock, after adding to the line.
    ///
    /// - Parameter state: The line.
    private func trim(_ state: inout State) {
        while state.line.count > maxLine {
            guard let oldest = state.line.lazy.compactMap({ slot -> Held? in
                if case .held(let held) = slot, !held.isSettled { return held }
                return nil
            }).first else { return }
            giveUp(oldest)
            release(&state)
        }
    }

    /// Send from the front of the line up to the first event still held. Call under the lock.
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
                if held.places.contains(.launchServices) { state.held -= 1 }
                if held.places.contains(.scan) { state.scanHeld -= 1 }
                send(held.isChanged ? restamped(held.event, reads: held.reads) : held.event)
            }
            sent += 1
        }
        state.line.removeFirst(sent)
    }

    /// Send a stamped event now, or queue it behind any held events.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - reads: When something changed it: does a set read that, so it's stamped again first?
    private func submit(_ event: Stamped, restamping reads: ((CompiledIndicators) -> Bool)? = nil) {
        state.withLockUnchecked { state in
            guard !state.isClosed else { return }
            let event = reads.map { restamped(event, reads: $0) } ?? event
            if state.line.isEmpty { return send(event) }
            state.line.append(.stamped(event))
            trim(&state)
        }
    }

    /// Advance a stamped event's sequences, then encode and emit it. Call under the lock, in the line's order.
    ///
    /// - Parameter event: The event.
    private func send(_ event: Stamped) {
        var message = event.message
        event.indicators?.advance(&message, steps: event.steps, values: &values, chains: event.chains)
        guard let json = try? encoder.encode(message) else {
            return Self.logger.fault("Couldn't encode an event a lane held, so it was dropped.")
        }
        emit(CapturedEvent(json: json, eventClass: eventClass))
    }
}
