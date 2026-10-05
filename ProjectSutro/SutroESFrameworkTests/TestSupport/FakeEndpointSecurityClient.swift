//
//  FakeEndpointSecurityClient.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
import os
@testable import SutroESFramework


// MARK: - Fake client
/// An Endpoint Security client that records each call and delivers the messages a test builds, since only root can
/// create a real one.
///
/// Thread-safe: a test can deliver messages from several threads while another stops the session.
final class FakeEndpointSecurityClient: EndpointSecurityClient {
    /// A call the session made, in order.
    enum Call: Equatable {
        case subscribe([es_event_type_t])
        case unsubscribe([es_event_type_t])
        case unsubscribeAll
        case muteProcess(pid: Int32)
        case setPathMute(PathMute, muted: Bool)
        case mutedPaths
        case sync
        case delete
        
        /// The call without its arguments.
        var kind: Kind {
            switch self {
            case .subscribe: return .subscribe
            case .unsubscribe: return .unsubscribe
            case .unsubscribeAll: return .unsubscribeAll
            case .muteProcess: return .muteProcess
            case .setPathMute: return .setPathMute
            case .mutedPaths: return .mutedPaths
            case .sync: return .sync
            case .delete: return .delete
            }
        }
    }
    
    /// A kind of call, such as one the client refuses.
    enum Kind: Hashable {
        case subscribe, unsubscribe, unsubscribeAll, muteProcess, setPathMute, mutedPaths, sync, delete
    }
    
    /// The client's state, behind ``lock``.
    private struct State {
        var calls: [Call] = []
        var handler: ((UnsafePointer<es_message_t>) -> Void)?
        var refusing: Set<Kind>
        /// Hold sync completions until ``releaseSyncs()``, rather than calling them right away.
        var holdsSyncs = false
        var heldSyncs: [() -> Void] = []
    }
    
    private let lock: OSAllocatedUnfairLock<State>
    /// What ``mutedPaths()`` lists: Endpoint Security's default mutes, as a test sets them.
    private let presetMutedPaths: [ESMutedPath]
    
    /// - Parameters:
    ///   - handler: The session's handler for this client's messages.
    ///   - refusing: The kinds of call to refuse.
    ///   - mutedPaths: What ``mutedPaths()`` lists.
    init(handler: @escaping (UnsafePointer<es_message_t>) -> Void, refusing: Set<Kind>, mutedPaths: [ESMutedPath]) {
        lock = OSAllocatedUnfairLock(uncheckedState: State(handler: handler, refusing: refusing))
        presetMutedPaths = mutedPaths
    }
    
    /// Every call so far, in order.
    var calls: [Call] {
        lock.withLockUnchecked { $0.calls }
    }
    
    /// The session's handler, until the client is deleted. A test can keep it to deliver a message the way Endpoint
    /// Security may still hand one over while the client is being deleted.
    var handler: ((UnsafePointer<es_message_t>) -> Void)? {
        lock.withLockUnchecked { $0.handler }
    }
    
    /// Calls of one kind.
    ///
    /// - Parameter kind: The kind.
    /// - Returns: Those calls, in order.
    func calls(_ kind: Kind) -> [Call] {
        calls.filter { $0.kind == kind }
    }
    
    /// Refuse, or stop refusing, a kind of call.
    ///
    /// - Parameters:
    ///   - kind: The kind of call.
    ///   - refused: `true` to refuse it.
    func setRefusing(_ kind: Kind, _ refused: Bool) {
        lock.withLockUnchecked { state in
            if refused { state.refusing.insert(kind) } else { state.refusing.remove(kind) }
        }
    }
    
    /// Hold every sync completion from now on until ``releaseSyncs()``, as Endpoint Security does while messages are
    /// still queued in front of the marker.
    func holdSyncs() {
        lock.withLockUnchecked { $0.holdsSyncs = true }
    }
    
    /// Call every held sync completion, as Endpoint Security does once the marker reaches the front of the queue, and
    /// stop holding them.
    func releaseSyncs() {
        let held = lock.withLockUnchecked { state -> [() -> Void] in
            state.holdsSyncs = false
            defer { state.heldSyncs = [] }
            return state.heldSyncs
        }
        held.forEach { $0() }
    }
    
    /// Hand a message to the session's handler on the calling thread, as Endpoint Security would on the client's
    /// queue. Does nothing once the client is deleted.
    ///
    /// - Parameter fixture: The message.
    func deliver(_ fixture: RawMessageFixture) {
        handler?(fixture.raw)
    }
    
    /// Record a call.
    ///
    /// - Parameter call: The call.
    /// - Returns: `false` if calls of its kind are refused.
    private func record(_ call: Call) -> Bool {
        lock.withLockUnchecked { state in
            state.calls.append(call)
            return !state.refusing.contains(call.kind)
        }
    }
    
    /// Record the call.
    ///
    /// - Parameter events: The events to add.
    /// - Returns: `false` if subscribing is refused, unless the list is empty: like the live client, that succeeds
    ///   without asking Endpoint Security.
    func subscribe(_ events: [es_event_type_t]) -> Bool {
        record(.subscribe(events)) || events.isEmpty
    }
    
    /// Record the call.
    ///
    /// - Parameter events: The events to drop.
    /// - Returns: `false` if unsubscribing is refused, unless the list is empty: like the live client, that succeeds
    ///   without asking Endpoint Security.
    func unsubscribe(_ events: [es_event_type_t]) -> Bool {
        record(.unsubscribe(events)) || events.isEmpty
    }
    
    /// Record the call.
    ///
    /// - Returns: `false` if unsubscribing from everything is refused.
    func unsubscribeAll() -> Bool {
        record(.unsubscribeAll)
    }
    
    /// Record the call with the process's ID.
    ///
    /// - Parameter token: The process's audit token.
    /// - Returns: `false` if muting processes is refused.
    func muteProcess(_ token: audit_token_t) -> Bool {
        record(.muteProcess(pid: token.pid()))
    }
    
    /// Record the call.
    ///
    /// - Parameters:
    ///   - mute: The mute.
    ///   - muted: `true` to mute, `false` to unmute.
    /// - Returns: `false` if path mutes are refused.
    func setPathMute(_ mute: PathMute, muted: Bool) -> Bool {
        record(.setPathMute(mute, muted: muted))
    }
    
    /// Record the call.
    ///
    /// - Returns: The preset muted paths, or none if listing them is refused.
    func mutedPaths() -> [ESMutedPath] {
        record(.mutedPaths) ? presetMutedPaths : []
    }
    
    /// Record the call. The fake hands each message to the handler as it's delivered, so every message before the call
    /// has been handled: the completion runs right away, unless syncs are held (``holdSyncs()``).
    ///
    /// - Parameter completion: The sync's completion.
    /// - Returns: `false` if syncs are refused, as before macOS 27: the completion is never called.
    func sync(_ completion: @escaping () -> Void) -> Bool {
        guard record(.sync) else { return false }
        let held = lock.withLockUnchecked { state -> Bool in
            if state.holdsSyncs { state.heldSyncs.append(completion) }
            return state.holdsSyncs
        }
        if !held { completion() }
        return true
    }
    
    /// Record the call and drop the handler, as `es_delete_client` does.
    ///
    /// - Returns: `false` if deletes are refused (Endpoint Security leaked the client's resources).
    @discardableResult
    func delete() -> Bool {
        defer {
            lock.withLockUnchecked { $0.handler = nil }
            /// `ESClient.h`: if the client is destroyed, all sync blocks are called.
            releaseSyncs()
        }
        return record(.delete)
    }
}


// MARK: - Fake factory
/// Makes ``FakeEndpointSecurityClient``s and keeps each one, in the order the session asked for them.
final class FakeEndpointSecurityClientFactory: EndpointSecurityClientFactory {
    /// Every client made, in order.
    private(set) var clients: [FakeEndpointSecurityClient] = []
    /// Refusals by request: `[1: .tooManyClients]` refuses the second client.
    private let refusals: [Int: NewClientResult]
    /// Kinds of call each client refuses, by request.
    private let refusing: [Int: Set<FakeEndpointSecurityClient.Kind>]
    /// What each client lists as muted, by request.
    private let mutedPaths: [Int: [ESMutedPath]]
    private var requests: Int = 0
    
    /// - Parameters:
    ///   - refusals: Refusals by request.
    ///   - refusing: Kinds of call each client refuses, by request.
    ///   - mutedPaths: What each client lists as muted, by request.
    init(refusals: [Int: NewClientResult] = [:], refusing: [Int: Set<FakeEndpointSecurityClient.Kind>] = [:],
         mutedPaths: [Int: [ESMutedPath]] = [:]) {
        self.refusals = refusals
        self.refusing = refusing
        self.mutedPaths = mutedPaths
    }
    
    /// Make the next client, or refuse it.
    ///
    /// - Parameter handler: The session's handler for the client's messages.
    /// - Returns: A new fake client.
    /// - Throws: ``ClientRefusal`` if this request is to be refused.
    func makeClient(handler: @escaping (UnsafePointer<es_message_t>) -> Void) throws -> any EndpointSecurityClient {
        defer { requests += 1 }
        if let refusal = refusals[requests] { throw ClientRefusal(result: refusal) }
        let client = FakeEndpointSecurityClient(handler: handler, refusing: refusing[requests] ?? [],
                                                mutedPaths: mutedPaths[requests] ?? [])
        clients.append(client)
        return client
    }
}
