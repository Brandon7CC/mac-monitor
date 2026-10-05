//
//  LineageLookup.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import CoreData


// MARK: - Lineage lookups
/// Finds a process's parents among stored events, in one context: each through the event that created the parent (its
/// exec or fork), by the indexed ``ESMessage/created_audit_token``. No other index is needed.
struct LineageLookup {
    /// The most launched-by parents ``launchedByParents(of:limit:)`` walks up.
    static let maxSteps = 64
    /// The most images of one process walked back to the fork that created it, for a parent known only by its pid.
    static let maxImages = 16
    /// The `event_type`s of the events that create a process: exec and fork.
    private static let creatingTypes = [ESMessage.execEventType, ESMessage.forkEventType]
    
    /// The context to fetch in.
    let context: NSManagedObjectContext
    
    /// - Parameter context: The context to fetch in. Use the lookup on its queue.
    init(_ context: NSManagedObjectContext) {
        self.context = context
    }
    
    /// The event that created a process: its exec, or without one its fork.
    ///
    /// - Parameter token: The process's audit token, in ``AuditToken/toString()``'s format.
    /// - Returns: The event, or `nil` when the store has neither, or `token` is empty (a process without a token).
    /// - Throws: The fetch's error.
    func creator(ofToken token: String) throws -> ESMessage? {
        guard !token.isEmpty else { return nil }
        return try creator(matching: NSPredicate(format: "created_audit_token == %@ AND event_type IN %@", token,
                                                 Self.creatingTypes))
    }
    
    /// The event that created a process image: by its whole token or, failing that, by its pid and pid version alone,
    /// which name one image (``AuditToken/isSameProcess(as:)``). A process that changed its ids after its exec (`sudo`)
    /// names itself to the processes it makes by other ids than its exec gave it.
    ///
    /// The pid and pid version are matched among the tokens that start with the pid, a range of the indexed
    /// ``ESMessage/created_audit_token``.
    ///
    /// - Parameter token: The image's audit token, in ``AuditToken/toString()``'s format.
    /// - Returns: The image's exec, or without one its fork; `nil` when the store has neither, or `token` is empty.
    /// - Throws: The fetch's error.
    func creator(ofImage token: String) throws -> ESMessage? {
        if let creator = try creator(ofToken: token) { return creator }
        guard token.hasPrefix("pid:"), let pid = token.range(of: ", "),
              let pidversion = token.range(of: ", pidversion:", options: .backwards) else { return nil }
        /// Every token of pid 42 sorts from "pid:42, " up to "pid:42,!".
        let lowest = String(token[..<pid.upperBound]), beyond = String(token[..<pid.lowerBound]) + ",!"
        let format = "created_audit_token >= %@ AND created_audit_token < %@ AND created_audit_token ENDSWITH %@ "
            + "AND event_type IN %@"
        return try creator(matching: NSPredicate(format: format, lowest, beyond,
                                                 String(token[pidversion.lowerBound...]), Self.creatingTypes))
    }
    
    /// The exec, or without one the fork, among the events that match.
    ///
    /// - Parameter predicate: Matches execs and forks.
    /// - Returns: The exec or fork, or `nil` when none matches.
    /// - Throws: The fetch's error.
    private func creator(matching predicate: NSPredicate) throws -> ESMessage? {
        let request = ESMessage.fetchRequest()
        request.predicate = predicate
        request.returnsObjectsAsFaults = false
        let creators = try context.fetch(request)
        return creators.first { $0.event_type == ESMessage.execEventType }
            ?? creators.first { $0.event_type == ESMessage.forkEventType }
    }
    
    /// The event that created the process an event is about: an exec or a fork itself (its target or child), and for
    /// any other event, the creator of the process that caused it.
    ///
    /// - Parameter event: The event.
    /// - Returns: The creator, or `nil` when the store doesn't have it.
    func creator(ofProcessOf event: ESMessage) -> ESMessage? {
        if event.createsProcess { return event }
        return event.instigator_audit_token.flatMap { try? creator(ofImage: $0) }
    }
    
    /// One step up: the launched-by parent of the process an exec or fork created, and the event that created that
    /// parent.
    ///
    /// - Parameter creator: The exec or fork.
    /// - Returns: The step, or `nil` when the event has no launched-by parent (it isn't an exec or fork).
    func step(from creator: ESMessage) -> LaunchedByParentStep? {
        guard let launchedByParent = creator.createdLaunchedByParent else { return nil }
        return LaunchedByParentStep(launchedByParent: launchedByParent,
                                    event: self.creator(of: launchedByParent, namedBy: creator))
    }
    
    /// The event that created a launched-by parent: found by its token (``creator(ofImage:)``), or for a parent known
    /// only by its pid, through the Unix chain of the process that named it.
    ///
    /// - Parameters:
    ///   - launchedByParent: The launched-by parent.
    ///   - creator: The exec or fork that named it.
    /// - Returns: The launched-by parent's creator, or `nil` when the store doesn't have it or LaunchServices named no
    ///   one.
    private func creator(of launchedByParent: LaunchedByParent, namedBy creator: ESMessage) -> ESMessage? {
        if let token = launchedByParent.audit_token { return try? self.creator(ofImage: token.toString()) }
        guard launchedByParent.source == .unixParent, let pid = launchedByParent.pid,
              pid > LaunchedByParent.launchdPID else {
            return nil
        }
        return originalParentCreator(pid: pid, of: creator)
    }
    
    /// The creator of a process's original parent, known only by its pid (`original_ppid`): launchd adopted the process
    /// before its exec, once that parent had exited.
    ///
    /// The process's own images lead back to it: each exec's instigator is the image before, created by an earlier
    /// exec of the same pid or, first, by the fork whose forking process is the original parent.
    ///
    /// - Parameters:
    ///   - pid: The original parent's pid.
    ///   - creator: The exec that named it.
    /// - Returns: The original parent's creator, or `nil` when the store doesn't lead to one with that pid.
    private func originalParentCreator(pid: Int32, of creator: ESMessage) -> ESMessage? {
        var image = creator
        for _ in 0..<Self.maxImages {
            guard let token = image.instigator_audit_token else { return nil }
            if image.event_type == ESMessage.forkEventType {
                return image.initiating_pid == pid ? try? self.creator(ofImage: token) : nil
            }
            guard let earlier = try? self.creator(ofImage: token), earlier.created_pid == image.created_pid else {
                return nil
            }
            image = earlier
        }
        return nil
    }
    
    /// The launched-by parents of the process an event is about, nearest first: its launched-by parent, that parent's,
    /// and so on.
    ///
    /// The walk ends after launchd (pid 1), at a parent the store doesn't have (a step without an event), at a
    /// LaunchServices answer that names no launcher, at a parent already walked, or after ``maxSteps`` steps.
    ///
    /// - Parameters:
    ///   - event: The event: an exec or fork is about the process it created, any other event about its instigator.
    ///   - limit: The most steps to return. Never more than ``maxSteps``.
    /// - Returns: The steps, nearest first. Empty when the store doesn't have the process's creator.
    func launchedByParents(of event: ESMessage, limit: Int = maxSteps) -> [LaunchedByParentStep] {
        guard var current = creator(ofProcessOf: event) else { return [] }
        var steps: [LaunchedByParentStep] = [], seen: Set<NSManagedObjectID> = [current.objectID]
        while steps.count < min(limit, Self.maxSteps), let step = step(from: current) {
            if let parent = step.event, !seen.insert(parent.objectID).inserted { break }
            steps.append(step)
            guard let parent = step.event, !step.launchedByParent.isLaunchd else { break }
            current = parent
        }
        return steps
    }
    
    /// The Unix parent and the launched-by parent of the process an exec or fork created.
    ///
    /// A fork's Unix parent is the forking process, as the message names it. An exec's is named by the event that
    /// created it, else by the launched-by parent when that's the same process, else as launchd when it's pid 1.
    ///
    /// - Parameter event: The exec or fork.
    /// - Returns: The parents, or `nil` for any other event.
    func parents(of event: ESMessage) -> ProcessParents? {
        guard event.createsProcess, let created = event.event.exec?.target ?? event.event.fork?.child else {
            return nil
        }
        let launchedBy = step(from: event)
        guard event.event_type == ESMessage.execEventType else {
            return ProcessParents(unix: .init(pid: event.initiating_pid, original_ppid: created.original_ppid,
                                              path: event.initiating_path), launchedByParent: launchedBy)
        }
        let named = (try? creator(ofImage: created.parent_audit_token_string))?.created_path
        let answered = launchedBy?.launchedByParent.pid == created.ppid ? launchedBy?.launchedByParent.path : nil
        let launchd = created.ppid == LaunchedByParent.launchdPID ? LaunchedByParent.launchdPath : nil
        return ProcessParents(unix: .init(pid: created.ppid, original_ppid: created.original_ppid,
                                          path: named ?? answered ?? launchd), launchedByParent: launchedBy)
    }
}
