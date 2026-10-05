//
//  LaunchedByParentUpgrader.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import OSLog
import os


// MARK: - Launched-by parent upgrader
/// Asks LaunchServices who launched each app Mac Monitor sees exec'd, after the event arrives, and hands back the
/// better answer (``LaunchedByParent/upgraded(with:for:path:)``).
///
/// The Security Extension names an app LaunchServices launched as a launchd job (`application.…`): the app checks in
/// with LaunchServices 2-5 ms after its exec. Mac Monitor runs in the console user's audit session, where
/// LaunchServices answers, so it reads the app's record at each of ``delays`` after the event arrives (by default at
/// once, then 50 and 250 ms later). The first record found ends the lookup: it gives an answer when it's for exactly
/// this exec and improves on the Security Extension's, and nothing otherwise.
///
/// Only an exec whose answer ``LaunchedByParent/needsLaunchServices``, whose target is in Mac Monitor's own audit
/// session (LaunchServices answers for the caller's), and that happened in the last ``maxAge`` seconds is looked up: an
/// event spooled while Mac Monitor was away comes too late for its app's record. At most ``maxPending`` lookups wait at
/// a time; past that, new ones are dropped and logged.
///
/// Without a ``reader`` (the default, and always in the Security Extension) nothing is looked up. Lookups run on the
/// upgrader's own utility queue, never on the XPC connection's queue or the main queue.
public final class LaunchedByParentUpgrader {
    /// Logs dropped lookups.
    static let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "LaunchedByParentUpgrader")
    /// When to read an app's record, in seconds after its event arrives.
    static let defaultDelays: [TimeInterval] = [0, 0.05, 0.25]
    /// The most lookups waiting at a time.
    static let defaultMaxPending = 64
    /// The oldest event looked up, in seconds.
    static let maxAge: TimeInterval = 10
    /// The `event_type` of an exec.
    private static let execType = Int(ESMessage.execEventType)
    
    /// Reads LaunchServices' records: Mac Monitor's own, set by the app. `nil` turns lookups off. Thread-safe.
    public var reader: LaunchServicesReading? {
        get { readerLock.withLockUnchecked { $0 } }
        set { readerLock.withLockUnchecked { $0 = newValue } }
    }
    /// Guards ``reader``.
    private let readerLock = OSAllocatedUnfairLock<LaunchServicesReading?>(uncheckedState: nil)
    
    /// When to read an app's record, in seconds after its event arrives.
    let delays: [TimeInterval]
    /// The most lookups waiting at a time.
    let maxPending: Int
    /// The audit session LaunchServices answers for: Mac Monitor's own.
    let session: Int32
    /// Names a launcher's executable from its pid and token (``ProcessPath/live``).
    private let path: (Int32, AuditToken?) -> String?
    /// The queue lookups run on.
    private let queue = DispatchQueue(label: "com.swiftlydetecting.agent.launchedByParentUpgrader", qos: .utility)
    /// Lookups waiting for a record, and lookups dropped because too many were. Only touched on ``queue``.
    private var pending = 0, dropped = 0
    
    /// An exec waiting for its app's record.
    private struct Lookup {
        /// The exec's `id`.
        let eventID: UUID
        /// The exec's target.
        let target: AuditToken
        /// The target's launched-by parent, as it arrived.
        let answer: LaunchedByParent
    }
    
    /// An upgrader for this process's audit session, with the default delays and bound, and no reader.
    public convenience init() {
        self.init(delays: Self.defaultDelays, maxPending: Self.defaultMaxPending,
                  session: audit_token_t.currentProcess.asid())
    }
    
    /// - Parameters:
    ///   - delays: When to read an app's record, in seconds after its event arrives, in order. At least one.
    ///   - maxPending: The most lookups waiting at a time.
    ///   - session: The audit session LaunchServices answers for.
    ///   - path: Names a launcher's executable from its pid and token.
    init(delays: [TimeInterval], maxPending: Int, session: Int32,
         path: @escaping (Int32, AuditToken?) -> String? = ProcessPath.live) {
        precondition(!delays.isEmpty, "A lookup reads at least once")
        self.delays = delays
        self.maxPending = maxPending
        self.session = session
        self.path = path
    }
    
    /// Look up the launcher of each app these events show exec'd. Cheap on the caller's queue: it picks the execs to
    /// look up, and the lookups run on the upgrader's queue.
    ///
    /// - Parameters:
    ///   - messages: Events as they arrived, in order.
    ///   - apply: Called on the upgrader's queue, at most once per exec, with the exec's `id` and its better answer.
    public func schedule(_ messages: [Message], apply: @escaping (UUID, LaunchedByParent) -> Void) {
        guard reader != nil else { return }
        let oldest = Date(timeIntervalSinceNow: -Self.maxAge)
        let lookups = messages.compactMap { lookup(for: $0, after: oldest) }
        guard !lookups.isEmpty else { return }
        let arrival = DispatchTime.now()
        queue.async {
            for lookup in lookups { self.begin(lookup, arrivedAt: arrival, apply: apply) }
        }
    }
    
    /// The lookup an event needs, if any.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - oldest: The oldest event looked up.
    /// - Returns: A lookup for an exec whose answer needs LaunchServices, whose target is in ``session``, and that
    ///   happened after `oldest`; `nil` for any other event.
    private func lookup(for message: Message, after oldest: Date) -> Lookup? {
        /// By `event_type` first: reading `event` copies it.
        guard message.event_type == Self.execType, message.message_darwin_time >= oldest,
              let exec = message.event.exec, let answer = exec.launched_by_parent, answer.needsLaunchServices,
              let target = exec.target.audit_token, target.asid == session else { return nil }
        return Lookup(eventID: message.id, target: target, answer: answer)
    }
    
    /// Start a lookup, unless ``maxPending`` are already waiting. On ``queue`` only.
    ///
    /// - Parameters:
    ///   - lookup: The lookup.
    ///   - arrival: When its event arrived.
    ///   - apply: Takes the better answer.
    private func begin(_ lookup: Lookup, arrivedAt arrival: DispatchTime,
                       apply: @escaping (UUID, LaunchedByParent) -> Void) {
        guard pending < maxPending else {
            dropped += 1
            Self.logger.info("Dropped a LaunchServices lookup: \(self.pending) waiting, \(self.dropped) dropped")
            return
        }
        pending += 1
        read(lookup, attempt: 0, arrivedAt: arrival, apply: apply)
    }
    
    /// Read the app's record at the attempt's delay after its event arrived, and settle the lookup or try again.
    ///
    /// - Parameters:
    ///   - lookup: The lookup.
    ///   - attempt: The index of the delay to read at.
    ///   - arrival: When its event arrived.
    ///   - apply: Takes the better answer.
    private func read(_ lookup: Lookup, attempt: Int, arrivedAt arrival: DispatchTime,
                      apply: @escaping (UUID, LaunchedByParent) -> Void) {
        queue.asyncAfter(deadline: arrival + delays[attempt]) {
            guard let reader = self.reader else {
                self.pending -= 1
                return
            }
            guard let record = reader.record(forPID: lookup.target.pid) else {
                if attempt + 1 < self.delays.count {
                    self.read(lookup, attempt: attempt + 1, arrivedAt: arrival, apply: apply)
                } else {
                    self.pending -= 1
                }
                return
            }
            /// An app's record doesn't change once it's there: for another exec, or naming a launcher LaunchServices
            /// has forgotten, a later read wouldn't do better.
            self.pending -= 1
            if let answer = lookup.answer.upgraded(with: record, for: lookup.target, path: self.path) {
                apply(lookup.eventID, answer)
            }
        }
    }
    
    /// Lookups waiting for a record, once lookups already scheduled have started.
    var pendingCount: Int {
        queue.sync { pending }
    }
}
