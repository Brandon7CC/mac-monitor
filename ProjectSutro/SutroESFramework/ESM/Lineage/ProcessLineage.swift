//
//  ProcessLineage.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation


// MARK: - Process lineage
/// The ancestors of every process the Security Extension knows of: who forked each one, and what program that was
/// (Security Extension context).
///
/// Endpoint Security names only a process's parent, and only while the parent lives: once it exits, the child's
/// parent reads as launchd. So the table is told of every fork, exec and exit, and keeps each process's ancestors as
/// they were when it was forked:
///
/// - **A fork** gives the child its parent's program, and the parent's own ancestors behind it.
/// - **An exec** gives the process a new program under a new key (``ProcessKey``), with the ancestors it had. The
///   programs a pid ran before aren't its ancestors.
/// - **An exit** forgets the process ``lingers`` seconds later, since another capture lane may still be handing over
///   its last events. Its descendants keep it as an ancestor for as long as they live.
///
/// A parent that execs again after forking a child stays, for that child, the program that forked it.
///
/// Beside who forked it, a program can have the process that really caused it to run (``LaunchedByParent``): an XPC
/// service's host app, the app that opened another. The launched-by chain (``Chain/launchedBy``) follows those, and
/// the forking process wherever there's none.
///
/// Processes that were running before the table was started are added from the process list (``seed(_:)``). A
/// process nothing was heard of is still listed as an ancestor, by its key alone.
///
/// It may be told of the same event twice, by its own client and by a capture lane that handles the event too
/// (``note(_:at:)``): the second telling changes nothing that matters.
///
/// **Threading:** thread-safe. Every call takes its lock, and none calls out while holding it.
public final class ProcessLineage: @unchecked Sendable {
    /// A chain of ancestors, by what an indicator's key paths for it start with.
    public enum Chain: String, CaseIterable, Sendable {
        /// The Unix parents: who forked whom.
        case lineage
        /// The launched-by parents: who really caused each one to run (``LaunchedByParent``), which is its Unix
        /// parent wherever nothing better is known.
        case launchedBy = "launched_by"
    }

    /// One program of one process, and the program that forked the process. Only read and changed under the lock.
    final class Node {
        var program: ProcessProgram
        var parent: Node?
        /// The process that really caused it to run, when that isn't the one that forked it. Its pid version is 0
        /// when only its pid is known.
        var launcher: ProcessKey?
        /// Did a lookup wait to be told of it and give up? Then no lookup waits for it again.
        var gaveUp = false

        /// - Parameters:
        ///   - program: The program.
        ///   - parent: The program that forked its process.
        init(_ program: ProcessProgram, parent: Node?) {
            self.program = program
            self.parent = parent
        }
    }

    /// How many ancestors a process is given: its nearest, and the first below launchd, which is kept when the chain
    /// is longer.
    public static let depth = 8
    /// How long a process stays after it exits, or a program after its process execs another.
    public static let lingers: TimeInterval = 10
    /// How far up a chain is walked for its first program below launchd.
    static let walkLimit = 128
    /// Reads a running process from the system, by its pid: its program and its parent's pid, or `nil` when it's
    /// gone (``RunningProcesses``). `nil` reads none.
    typealias Reader = (Int32) -> (program: ProcessProgram, parent: Int32)?

    /// Reads the parents of a process the table hasn't been told of (``ancestors(of:parent:reading:chain:)``).
    let reader: Reader?
    /// Is it a trace's table (``replaying()``)? Then nothing is forgotten and nothing is found by its pid alone.
    private var isReplay = false
    /// How long a lookup waits at most to be told of a process that's gone from the system too. Endpoint Security
    /// holds a quiet client's events back: on an idle macOS 27.2 the table's own client heard of 101 execs a median
    /// of 240 ms after they happened and 260 ms at most, while a client told of every file created and closed had
    /// its events within a few milliseconds.
    let patience: TimeInterval
    /// How long lookups may wait in vain in any one second. Past it, a lookup that would wait gives up at once, so
    /// a table that's no longer told of anything can't hold a capture lane up. A wait that was answered isn't
    /// counted: it lasts only as long as the table's own client is behind.
    let waitBudget: TimeInterval
    /// Guards the table, and wakes the lookups waiting to be told of a process.
    let lock = NSCondition()
    /// How many lookups read a process's parents from the system, and how many of those learned nothing.
    var discovered = 0, unanswered = 0
    /// How many lookups waited to be told of a process, and the longest any did, in seconds.
    var waited = 0, longestWait: TimeInterval = 0
    /// When the second being budgeted began, on the system's uptime, and how long lookups have waited in vain in it.
    var windowStart: TimeInterval = 0, waitedInWindow: TimeInterval = 0
    /// The time of the latest event the table's own client told it of, on Endpoint Security's clock
    /// (``told(upTo:)``).
    var toldUpTo: UInt64 = 0
    /// How many lookups are waiting to be told of a process.
    var waiting = 0
    /// Every program known, by its key.
    var nodes: [ProcessKey: Node] = [:]
    /// The newest program known of each pid: the one a later program of the pid has the ancestors of.
    var newest: [Int32: Node] = [:]
    /// The programs to forget, oldest first, and when each stopped running.
    private var gone: [(key: ProcessKey, at: TimeInterval)] = []
    /// How many of ``gone`` were forgotten already, so forgetting never shifts the array.
    private var forgotten = 0

    public convenience init() {
        self.init(reader: nil)
    }

    /// A table for a trace that's read whole before anything is asked of it (``TraceLineage``). It keeps every
    /// program, and finds a process by its own key only: the newest program of a pid is whatever the pid ran last
    /// in the whole trace, which can be another process that reused the pid.
    ///
    /// - Returns: The table.
    static func replaying() -> ProcessLineage {
        let table = ProcessLineage(reader: nil)
        table.isReplay = true
        return table
    }

    /// - Parameters:
    ///   - reader: Reads a running process, for the parents of one the table hasn't been told of.
    ///   - patience: How long a lookup waits to be told of a process that's gone from the system too.
    ///   - waitBudget: How long lookups may wait in all in any one second.
    init(reader: Reader?, patience: TimeInterval = 0.3, waitBudget: TimeInterval = 0.3) {
        self.reader = reader
        self.patience = patience
        self.waitBudget = waitBudget
    }

    /// How many programs the table holds.
    public var count: Int {
        lock.withLock { nodes.count }
    }

    /// How many lookups read a process's parents from the system because the table hadn't been told of them, and
    /// how many of those learned nothing: the parent was gone too.
    public var discoveries: (read: Int, unanswered: Int) {
        lock.withLock { (discovered, unanswered) }
    }

    /// How many lookups waited to be told of a process that was gone from the system, and the longest any did, in
    /// seconds.
    public var waits: (count: Int, longest: TimeInterval) {
        lock.withLock { (waited, longestWait) }
    }

    // MARK: Events

    /// A process forked a child, which runs its program until it execs another. A child launchd forks has no
    /// ancestors, and is known by its key alone until it execs.
    ///
    /// - Parameters:
    ///   - child: The child.
    ///   - parent: The process that forked it.
    ///   - launchedBy: The process that really caused the child to run, when that's another and it's known. A
    ///     second telling of the fork that doesn't say keeps what the first said.
    public func fork(_ child: ProcessKey, from parent: ProcessKey, launchedBy: ProcessKey? = nil) {
        lock.withLock {
            let launcher = launchedBy ?? nodes[child]?.launcher
            guard !parent.isRoot else {
                keep(Node(ProcessProgram(key: child), parent: nil), launchedBy: launcher)
                return
            }
            let parent = node(parent)
            var program = parent.program
            program.key = child
            keep(filling(program, parent: parent), launchedBy: launcher)
        }
    }

    /// A process exec'd a program.
    ///
    /// - Parameters:
    ///   - program: The program it runs now, under its new key.
    ///   - previous: The key it had before.
    ///   - parent: Its parent as the exec names it, for a process the table wasn't told of.
    ///   - launchedBy: The process that really caused the program to run, when that's another and it's known. A
    ///     second telling of the exec that doesn't say keeps what the first said.
    ///   - now: The time, in seconds on any clock that doesn't go back.
    public func exec(_ program: ProcessProgram, replacing previous: ProcessKey, parent: ProcessKey? = nil,
                     launchedBy: ProcessKey? = nil, at now: TimeInterval) {
        lock.withLock {
            let before = nodes[previous]
            let launcher = launchedBy ?? nodes[program.key]?.launcher
            keep(filling(program, parent: before?.parent ?? parent.flatMap { $0.isRoot ? nil : node($0) }),
                 launchedBy: launcher)
            if before != nil, previous != program.key { linger(previous, at: now) }
            forget(at: now)
        }
    }

    /// Say who really caused a program to run, once it's known: Launch Services answers after an app's exec.
    ///
    /// - Parameters:
    ///   - launcher: The process that caused it to run, or `nil` for the one that forked it.
    ///   - key: The program.
    public func setLauncher(_ launcher: ProcessKey?, of key: ProcessKey) {
        lock.withLock {
            guard let node = nodes[key] else { return }
            node.launcher = launcher == node.parent?.program.key ? nil : launcher
        }
    }

    /// A process exited.
    ///
    /// - Parameters:
    ///   - key: The process.
    ///   - now: The time, in seconds on any clock that doesn't go back.
    public func exit(_ key: ProcessKey, at now: TimeInterval) {
        lock.withLock {
            if nodes[key] != nil { linger(key, at: now) }
            forget(at: now)
        }
    }

    /// Forget everything: the table stopped being told of events, so what it holds would go stale.
    public func removeAll() {
        lock.withLock {
            nodes = [:]
            newest = [:]
            toldUpTo = 0
            (discovered, unanswered, waited, longestWait) = (0, 0, 0, 0)
            gone = []
            forgotten = 0
        }
    }

    // MARK: Lookups

    /// What's known of a program.
    ///
    /// - Parameter key: The program's key.
    /// - Returns: The program, or `nil` when the table has nothing under the key.
    public func program(_ key: ProcessKey) -> ProcessProgram? {
        lock.withLock { nodes[key]?.program }
    }

    /// A process's ancestors, nearest first: its parent, its parent's parent, and so on up to the first below
    /// launchd, which isn't listed. At most ``depth``: of a longer chain, the nearest and the first below launchd.
    ///
    /// A capture lane may be ahead of the table's own client, which Endpoint Security can hold back by a quarter
    /// of a second (``patience``). So a program the table hasn't been told of yet is looked for by the newest
    /// program known of its pid, which has the same ancestors, and then by the parent its event names, in the same
    /// way.
    ///
    /// When the table knows neither, or knows the nearest ancestor by its key alone, the lookup can read the
    /// parents from the system instead, which takes microseconds: each running parent's path and command line, up
    /// to one the table knows. What it reads has no signature, which only the parent's own exec tells, and stands
    /// until that exec is reported.
    ///
    /// A parent that's gone from the system too belongs to a process tree that has already ended, whose fork and
    /// exec the table's client hasn't handed over yet. The lookup waits until the client is told of an event as
    /// late as the one being looked up (``told(upTo:)``), by when it has been told of them, and ``patience`` at
    /// most. If it isn't told, the parent is kept by its key alone and no lookup waits for it again.
    ///
    /// - Parameters:
    ///   - key: The process, by the program it runs.
    ///   - parent: Its parent as its event names it, for a process the table hasn't been told of yet.
    ///   - reading: Read the parents from the system, and wait for one that's gone, when the table doesn't know
    ///     the nearest ancestor?
    ///   - time: The time of the event being looked up, on Endpoint Security's clock (`mach_time`): a lookup
    ///     doesn't wait once the table's client was told of a later event. `nil` waits out its patience.
    ///   - chain: Which ancestors: the ones that forked each other, or the ones that caused each other to run.
    /// - Returns: The ancestors. Empty for a child of launchd, and for a process nothing is known of.
    public func ancestors(of key: ProcessKey, parent: ProcessKey? = nil, reading: Bool = false,
                          at time: UInt64? = nil, chain: Chain = .lineage) -> [ProcessProgram] {
        if reading, let reader, let missing = lock.withLock({ missing(for: key, parent: parent) }) {
            discover(missing, at: time, with: reader)
        }
        return lock.withLock {
            var next = find(key).map { step(from: $0, along: chain) } ?? parent.flatMap(find)
            var ancestors: [ProcessProgram] = []
            var walked = Set<ObjectIdentifier>()
            /// Launched-by parents can name each other, so a program met twice ends the chain.
            while let node = next, walked.count < Self.walkLimit, !node.program.key.isRoot,
                  walked.insert(ObjectIdentifier(node)).inserted {
                if ancestors.count < Self.depth {
                    ancestors.append(node.program)
                } else {
                    ancestors[Self.depth - 1] = node.program
                }
                next = step(from: node, along: chain)
            }
            return ancestors
        }
    }

    // MARK: Under the lock

    /// The node for a key, made with nothing but the key when there's none. Call under the lock.
    ///
    /// - Parameter key: A program's key.
    /// - Returns: Its node.
    func node(_ key: ProcessKey) -> Node {
        if let node = nodes[key] { return node }
        let node = Node(ProcessProgram(key: key), parent: nil)
        keep(node)
        return node
    }

    /// The next program up a chain. Call under the lock.
    ///
    /// - Parameters:
    ///   - node: A program.
    ///   - chain: The chain.
    /// - Returns: The program that forked it, or along the launched-by chain the one that caused it to run when
    ///   that's another the table knows. `nil` at launchd.
    private func step(from node: Node, along chain: Chain) -> Node? {
        guard chain == .launchedBy, let launcher = node.launcher else { return node.parent }
        return launcher.isRoot ? nil : find(launcher) ?? node.parent
    }

    /// Keep a node under its key, and as its pid's newest program if it is, and wake the lookups waiting to be
    /// told of a process. Call under the lock.
    ///
    /// - Parameters:
    ///   - node: The node.
    ///   - launcher: The process that really caused it to run, which is kept only when it isn't the one that
    ///     forked it.
    /// The node for a program an event created. One known by its key alone is filled in where it stands, since its
    /// children already point at it: a child's event can come before its parent's, as a held app exec's does.
    ///
    /// - Parameters:
    ///   - program: The program.
    ///   - parent: The program that forked its process.
    /// - Returns: The node, to keep.
    private func filling(_ program: ProcessProgram, parent: Node?) -> Node {
        guard let known = nodes[program.key], !known.program.isKnown, known !== parent else {
            return Node(program, parent: parent)
        }
        known.program = program
        if known.parent == nil { known.parent = parent }
        return known
    }

    func keep(_ node: Node, launchedBy launcher: ProcessKey? = nil) {
        node.launcher = launcher == node.parent?.program.key ? nil : launcher
        let key = node.program.key
        nodes[key] = node
        if (newest[key.pid]?.program.key.pidversion ?? -1) <= key.pidversion { newest[key.pid] = node }
        lock.broadcast()
    }

    /// The node for a key, or else for the newest program known of its pid: the one it ran before, when the table
    /// hasn't been told of the exec yet, or the one it ran next, when the program asked for is forgotten. Either
    /// has the same ancestors. Call under the lock.
    ///
    /// - Parameter key: A program's key.
    /// - Returns: The node, or `nil` when the table knows no program of the pid.
    func find(_ key: ProcessKey) -> Node? {
        nodes[key] ?? (isReplay ? nil : newest[key.pid])
    }

    /// Note a program that stopped running, to forget it later. Call under the lock.
    ///
    /// - Parameters:
    ///   - key: The program's key.
    ///   - now: The time.
    private func linger(_ key: ProcessKey, at now: TimeInterval) {
        if !isReplay { gone.append((key, now)) }
    }

    /// Forget the programs that stopped running ``lingers`` seconds ago or longer. Call under the lock.
    ///
    /// - Parameter now: The time.
    private func forget(at now: TimeInterval) {
        while forgotten < gone.count, gone[forgotten].at + Self.lingers <= now {
            let key = gone[forgotten].key
            if let node = nodes.removeValue(forKey: key), newest[key.pid] === node { newest[key.pid] = nil }
            forgotten += 1
        }
        guard forgotten > 1_024, forgotten * 2 > gone.count else { return }
        gone.removeFirst(forgotten)
        forgotten = 0
    }
}
