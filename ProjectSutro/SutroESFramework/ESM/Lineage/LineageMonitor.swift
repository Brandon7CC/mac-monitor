//
//  LineageMonitor.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation
import EndpointSecurity
import OSLog


// MARK: - Lineage monitor
/// Keeps ``ProcessLineage`` told of every fork, exec and exit, with an Endpoint Security client of its own
/// (Security Extension context).
///
/// A capture session's clients can't be relied on for this: a session subscribes to what someone chose, mutes
/// paths, and builds no events while it isn't recording. This client subscribes to the three events and mutes
/// nothing but the Security Extension itself, so the table is whole whatever the sessions do.
///
/// Starting it subscribes first and then adds the processes already running (``RunningProcesses``), off the
/// caller's queue, so no process is missed between the two. A capture session waits for them before its lanes
/// take events (``waitUntilSeeded(timeout:)``).
///
/// Capture sessions share one (``shared``): it runs while any of them captures (``acquire()``, ``release()``), so
/// nothing runs while nobody does, and the client counts against Endpoint Security's limit only then.
///
/// **Threading:** thread-safe. The client's handler runs on the client's own queue.
public final class LineageMonitor: @unchecked Sendable {
    /// The one the Security Extension's capture sessions share.
    public static let shared = LineageMonitor()

    /// The table it keeps.
    public let lineage: ProcessLineage
    private let factory: any EndpointSecurityClientFactory
    private let clock: () -> TimeInterval
    private let running: () -> [(program: ProcessProgram, parent: Int32)]
    private let arguments: ProcessLineage.ArgumentReader
    /// Guards ``client`` and ``users``.
    private let lock = NSLock()
    private var client: (any EndpointSecurityClient)?
    /// How many capture sessions hold it running.
    private var users = 0
    private let seeding = DispatchQueue(label: "com.swiftlydetecting.sutro.lineage-seed", qos: .utility)
    /// Entered at each start, and left once the processes that were running then are added.
    private let seedingDone = DispatchGroup()
    private static let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "lineage")

    /// The events it's told of.
    static let events = [ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT]

    /// A monitor on Endpoint Security itself, whose table reads the system for the parents of a process it hasn't
    /// been told of.
    public convenience init() {
        self.init(lineage: ProcessLineage { RunningProcesses.process($0, signature: false) },
                  factory: LiveEndpointSecurityClientFactory())
    }

    /// - Parameters:
    ///   - lineage: The table to keep.
    ///   - factory: Makes its client.
    ///   - clock: The time, in seconds on a clock that doesn't go back.
    ///   - running: Reads the processes running now.
    ///   - arguments: Reads an exec's arguments.
    init(lineage: ProcessLineage, factory: any EndpointSecurityClientFactory,
         clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         running: @escaping () -> [(program: ProcessProgram, parent: Int32)] = { RunningProcesses.read() },
         arguments: @escaping ProcessLineage.ArgumentReader = ProcessHelpers.parseExecArgs(execEvent:)) {
        self.lineage = lineage
        self.factory = factory
        self.clock = clock
        self.running = running
        self.arguments = arguments
    }

    /// Is it being told of events?
    public var isRunning: Bool {
        lock.withLock { client != nil }
    }

    /// The table, while it's being told of events: `nil` otherwise, when what it holds says nothing of the
    /// processes running now.
    public var table: ProcessLineage? {
        lock.withLock { client != nil ? lineage : nil }
    }

    /// Hold it running for a capture session, starting it for the first.
    ///
    /// A session captures all the same when Endpoint Security refuses the client: its execs and forks then say
    /// nothing of their ancestors.
    ///
    /// - Parameter seeded: Called once the running processes are added, when this call started it.
    /// - Returns: `nil` when it's being told of events, else why Endpoint Security refused the client.
    @discardableResult
    public func acquire(seeded: (() -> Void)? = nil) -> NewClientResult? {
        lock.withLock {
            users += 1
            return start(seeded: seeded)
        }
    }

    /// Wait until the processes that were running when it started are in the table.
    ///
    /// - Parameter timeout: How long to wait at most.
    /// - Returns: Whether they're in. `true` for a monitor that never started.
    @discardableResult
    public func waitUntilSeeded(timeout: DispatchTimeInterval) -> Bool {
        seedingDone.wait(timeout: .now() + timeout) == .success
    }

    /// Let it go for a capture session that stopped, stopping it after the last.
    public func release() {
        lock.withLock {
            users = max(users - 1, 0)
            if users == 0 { stop() }
        }
    }

    /// Start: make the client, subscribe, then add the processes already running. Does nothing once started. Call
    /// under the lock.
    ///
    /// - Parameter seeded: Called once the running processes are added, on a queue of the monitor's own.
    /// - Returns: `nil` once it's told of events, else why Endpoint Security refused.
    @discardableResult
    private func start(seeded: (() -> Void)? = nil) -> NewClientResult? {
        guard client == nil else { return nil }
        let lineage = lineage, clock = clock, arguments = arguments
        let made: any EndpointSecurityClient
        do {
            made = try factory.makeClient { message in lineage.note(message, at: clock(), arguments: arguments) }
        } catch let refusal as ClientRefusal {
            Self.logger.error("No lineage client: \(String(describing: refusal.result), privacy: .public)")
            return refusal.result
        } catch {
            Self.logger.error("No lineage client: \(String(describing: error), privacy: .public)")
            return .internalSubsystem
        }
        _ = made.muteProcess(audit_token_t.currentProcess)
        guard made.subscribe(Self.events) else {
            made.delete()
            Self.logger.error("The lineage client couldn't subscribe.")
            return .internalSubsystem
        }
        client = made
        let running = running, done = seedingDone
        done.enter()
        seeding.async {
            let began = DispatchTime.now().uptimeNanoseconds
            let processes = running()
            lineage.seed(processes)
            let took = (DispatchTime.now().uptimeNanoseconds - began) / 1_000_000
            Self.logger.log("Lineage started with \(processes.count) running processes in \(took) ms.")
            seeded?()
            done.leave()
        }
        return nil
    }

    /// Stop being told of events, and empty the table: what it held goes stale at once. Call under the lock.
    private func stop() {
        _ = client?.unsubscribeAll()
        client?.delete()
        if client != nil {
            let discoveries = lineage.discoveries
            let waits = lineage.waits
            Self.logger.log("""
                Lineage stopped with \(self.lineage.count) programs. \(discoveries.read) lookups read a process's \
                parents from the system. \(waits.count) of them waited to be told of one that was gone, \
                \(Int(waits.longest * 1_000_000)) microseconds at most, and \(discoveries.unanswered) never were.
                """)
        }
        client = nil
        lineage.removeAll()
    }
}
