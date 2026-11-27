//
//  ProcessLineage+Discovery.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/18/26.
//

import Foundation


// MARK: - Processes the table wasn't told of yet
extension ProcessLineage {
    /// The table's own client was told of an event: Endpoint Security hands a client its events in order, so the
    /// table now knows every process forked or exec'd up to then. A lookup that's waiting for one stops.
    ///
    /// - Parameter time: The event's time, on Endpoint Security's clock (`mach_time`).
    public func told(upTo time: UInt64) {
        lock.withLock {
            guard time > toldUpTo else { return }
            toldUpTo = time
            if waiting > 0 { lock.broadcast() }
        }
    }

    /// The nearest ancestor a lookup has to learn of before it can answer: the parent the event names when the
    /// table knows neither it nor the process, the process itself when its event names no parent, as a network
    /// flow's doesn't, or the nearest ancestor the table has when that's known by its key alone, as the parent of an
    /// exec a capture lane told the table of first. Call under the lock.
    ///
    /// - Parameters:
    ///   - key: The process.
    ///   - parent: Its parent as its event names it.
    /// - Returns: The ancestor's key, or `nil` when there's nothing to learn.
    func missing(for key: ProcessKey, parent: ProcessKey?) -> ProcessKey? {
        if let node = find(key) {
            guard let nearest = node.parent, lacks(nearest.program.key) else { return nil }
            return nearest.program.key
        }
        guard let parent else { return key.isRoot ? nil : key }
        guard !parent.isRoot, lacks(parent) else { return nil }
        return parent
    }

    /// Is a process still to be learned of? One the table has nothing of is, and so is one it knows by its key
    /// alone with no parent, unless a lookup already gave up on it. Call under the lock.
    ///
    /// - Parameter key: The process.
    /// - Returns: Whether it is.
    private func lacks(_ key: ProcessKey) -> Bool {
        guard let node = find(key) else { return true }
        return !node.program.isKnown && node.parent == nil && !node.gaveUp
    }

    /// Read a process and its parents from the system and add them, up to one the table knows, launchd, or
    /// ``depth`` of them. For one that's gone, wait until the table's client is told of it or of an event as late
    /// as the lookup's, within the lookup's patience and the second's budget, and keep it by its key alone if
    /// nothing comes. Call without the lock: reading takes no lock.
    ///
    /// - Parameters:
    ///   - target: The process to start from: the nearest ancestor the lookup has to learn of.
    ///   - time: The time of the event being looked up, or `nil` to wait out the patience.
    ///   - reader: Reads a running process.
    func discover(_ target: ProcessKey, at time: UInt64?, with reader: Reader) {
        var running: [(program: ProcessProgram, parent: Int32)] = []
        var pid = target.pid
        while pid > ProcessKey.launchd, running.count < Self.depth, let process = reader(pid) {
            running.append(process)
            if lock.withLock({ nodes[process.program.key]?.program.isKnown == true }) { break }
            pid = process.parent
        }
        seed(running)
        lock.withLock {
            discovered += 1
            /// A process that exec'd since its child named it is read under its new key: its ancestors are the same.
            if let node = nodes[target], lacks(target), let newer = newest[target.pid], newer !== node {
                node.parent = newer.parent
            }
            guard lacks(target) else { return }
            awaitTold(upTo: time) { !lacks(target) }
            guard lacks(target) else { return }
            unanswered += 1
            let node = find(target) ?? Node(ProcessProgram(key: target), parent: nil)
            node.gaveUp = true
            if nodes[target] == nil { keep(node) }
        }
    }

    /// A process's command line, by its own key, never by another program of its pid. One the table hasn't been
    /// told of is read from the system, with its parents, and waited for when it isn't running as that program, as
    /// an ancestor is (``ancestors(of:parent:reading:at:chain:)``). Without a reader, as in a replay, the table's
    /// own is answered at once.
    ///
    /// - Parameters:
    ///   - key: The process.
    ///   - time: The time of the event being looked up, on Endpoint Security's clock.
    /// - Returns: Its command line, or `nil` when it isn't known.
    public func commandLine(of key: ProcessKey, at time: UInt64) -> String? {
        guard let reader, !key.isRoot, lock.withLock({ nodes[key]?.program.isKnown != true }) else {
            return lock.withLock { nodes[key]?.program.commandLine }
        }
        discover(key, at: time, with: reader)
        return program(key, toldUpTo: time)?.program.commandLine
    }

    /// A program and the token it was told of, once the table's own client is told of an event as late as a
    /// flow's: a flow can come before its process's exec, which the table hears of about a quarter of a second late.
    ///
    /// - Parameters:
    ///   - key: The program's key.
    ///   - time: The flow's time, on Endpoint Security's clock.
    /// - Returns: The program and its token, or `nil` when the table has nothing under the key.
    func program(_ key: ProcessKey, toldUpTo time: UInt64) -> (program: ProcessProgram, token: audit_token_t?)? {
        lock.withLock {
            awaitTold(upTo: time) { nodes[key]?.program.isKnown == true }
            return nodes[key].map { ($0.program, $0.token) }
        }
    }

    /// The newest program of a pid and the token it was told of, once the table's own client is told of an event
    /// as late as a flow's: for a process that was reaped before its socket was read.
    ///
    /// - Parameters:
    ///   - pid: The pid.
    ///   - time: The flow's time, on Endpoint Security's clock.
    /// - Returns: The program and its token, or `nil` when the table knows no program of the pid.
    func newestProgram(of pid: Int32, toldUpTo time: UInt64) -> (program: ProcessProgram, token: audit_token_t?)? {
        lock.withLock {
            awaitTold(upTo: time) { false }
            return newest[pid].map { ($0.program, $0.token) }
        }
    }

    /// Wait until the table's own client is told of an event as late as a lookup's, or the lookup has its answer,
    /// within the patience and the second's budget. A wait that ends unanswered is charged to the budget. Call
    /// under the lock.
    ///
    /// - Parameters:
    ///   - time: The time of the event being looked up, or `nil` to wait out the patience.
    ///   - answered: Has the lookup its answer?
    private func awaitTold(upTo time: UInt64?, unless answered: () -> Bool) {
        let started = ProcessInfo.processInfo.systemUptime
        if started - windowStart >= 1 { (windowStart, waitedInWindow) = (started, 0) }
        let event = time ?? .max
        guard !answered(), toldUpTo < event, waitedInWindow < waitBudget else { return }
        let deadline = Date(timeIntervalSinceNow: patience)
        waiting += 1
        while !answered(), toldUpTo < event, lock.wait(until: deadline) {}
        waiting -= 1
        let elapsed = ProcessInfo.processInfo.systemUptime - started
        waited += 1
        longestWait = max(longestWait, elapsed)
        if !answered(), toldUpTo < event { waitedInWindow += elapsed }
    }
}
