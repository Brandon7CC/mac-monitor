//
//  LiveEndpointSecurityClient.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import EndpointSecurity


// MARK: - Live client
/// An Endpoint Security client that `es_new_client` created.
///
/// Not thread-safe on its own: its capture session makes every call on one serial queue (see
/// ``EndpointSecurityClient``).
final class LiveEndpointSecurityClient: EndpointSecurityClient {
    /// The client, until it's deleted.
    private var client: OpaquePointer?
    
    /// - Parameter client: A client `es_new_client` just created. This object deletes it.
    init(_ client: OpaquePointer) {
        self.client = client
    }
    
    /// `es_subscribe`.
    ///
    /// - Parameter events: The events to add.
    /// - Returns: `true` if Endpoint Security accepted them, or the list is empty.
    func subscribe(_ events: [es_event_type_t]) -> Bool {
        guard let client else { return false }
        guard !events.isEmpty else { return true }
        return es_subscribe(client, events, UInt32(events.count)) == ES_RETURN_SUCCESS
    }
    
    /// `es_unsubscribe`.
    ///
    /// - Parameter events: The events to drop.
    /// - Returns: `true` if Endpoint Security accepted the request, or the list is empty.
    func unsubscribe(_ events: [es_event_type_t]) -> Bool {
        guard let client else { return false }
        guard !events.isEmpty else { return true }
        return es_unsubscribe(client, events, UInt32(events.count)) == ES_RETURN_SUCCESS
    }
    
    /// `es_unsubscribe_all`.
    ///
    /// - Returns: `true` on success.
    func unsubscribeAll() -> Bool {
        guard let client else { return false }
        return es_unsubscribe_all(client) == ES_RETURN_SUCCESS
    }
    
    /// `es_mute_process`.
    ///
    /// - Parameter token: The process's audit token.
    /// - Returns: `true` on success.
    func muteProcess(_ token: audit_token_t) -> Bool {
        guard let client else { return false }
        var token = token
        return es_mute_process(client, &token) == ES_RETURN_SUCCESS
    }
    
    /// `es_mute_path` or `es_mute_path_events`, or their unmute counterparts, by whether the mute names events.
    ///
    /// - Parameters:
    ///   - mute: The path, its type, and its events.
    ///   - muted: `true` to mute, `false` to unmute.
    /// - Returns: `true` if Endpoint Security accepted the request. `false` for an empty path.
    func setPathMute(_ mute: PathMute, muted: Bool) -> Bool {
        guard let client, !mute.path.isEmpty else { return false }
        let events = mute.events
        let result: es_return_t
        switch (muted, events.isEmpty) {
        case (true, true):
            result = es_mute_path(client, mute.path, mute.type)
        case (true, false):
            result = es_mute_path_events(client, mute.path, mute.type, events, events.count)
        case (false, true):
            result = es_unmute_path(client, mute.path, mute.type)
        case (false, false):
            result = es_unmute_path_events(client, mute.path, mute.type, events, events.count)
        }
        return result == ES_RETURN_SUCCESS
    }
    
    /// `es_sync_client`, looked up when first used: it's new in macOS 27, so this builds with SDKs that don't declare
    /// it and runs on macOS that doesn't have it.
    ///
    /// - Parameter completion: Called once every message already queued has been handled.
    /// - Returns: `false` if the client is deleted, this macOS has no `es_sync_client`, or it refused.
    func sync(_ completion: @escaping () -> Void) -> Bool {
        guard let client, let syncClient = Self.syncClient else { return false }
        return syncClient(client, completion) == ES_RETURN_SUCCESS
    }
    
    /// Does this macOS have `es_sync_client`?
    static var supportsSync: Bool {
        syncClient != nil
    }
    
    /// `es_sync_client`'s C signature.
    ///
    /// The block escapes: Endpoint Security keeps it until the sync marker reaches the front of the client's queue.
    /// As a non-escaping block, Swift traps when the call returns with the block still retained.
    private typealias SyncClient =
        @convention(c) (OpaquePointer, @escaping @convention(block) () -> Void) -> es_return_t
    
    /// `es_sync_client`, or `nil` before macOS 27.
    private static let syncClient: SyncClient? = {
        /// `RTLD_DEFAULT`: search every image loaded, which includes `libEndpointSecurity`.
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "es_sync_client") else { return nil }
        return unsafeBitCast(symbol, to: SyncClient.self)
    }()
    
    /// `es_muted_paths_events`.
    ///
    /// - Returns: Every muted path, or none if Endpoint Security doesn't list them.
    func mutedPaths() -> [ESMutedPath] {
        guard let client, let paths = fetch_muted_paths(client) else { return [] }
        defer { release_es_memory(paths) }
        return (0..<paths.pointee.count).map { ESMutedPath(fromRawESPath: paths.pointee.paths[$0]) }
    }
    
    /// `es_delete_client`, once.
    ///
    /// - Returns: `false` if Endpoint Security leaked the client's resources.
    @discardableResult
    func delete() -> Bool {
        guard let client else { return true }
        /// The pointer is invalid after this either way: on `ES_RETURN_ERROR` Endpoint Security has still torn the
        /// client down, leaking its resources (`ESClient.h`).
        self.client = nil
        return es_delete_client(client) == ES_RETURN_SUCCESS
    }
}


// MARK: - Live factory
/// Makes clients with `es_new_client`. Needs root, the Endpoint Security entitlement, and Full Disk Access.
struct LiveEndpointSecurityClientFactory: EndpointSecurityClientFactory {
    /// A factory for live clients.
    init() {}
    
    /// `es_new_client`.
    ///
    /// - Parameter handler: Called for each message, serially, on the client's queue.
    /// - Returns: The new client.
    /// - Throws: ``ClientRefusal`` with the refusal `es_new_client` returned.
    func makeClient(handler: @escaping (UnsafePointer<es_message_t>) -> Void) throws
        -> any EndpointSecurityClient {
        var client: OpaquePointer?
        let result = es_new_client(&client) { _, message in handler(message) }
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
            let refusal = result == ES_NEW_CLIENT_RESULT_SUCCESS ? .internalSubsystem : NewClientResult(result)
            throw ClientRefusal(result: refusal)
        }
        return LiveEndpointSecurityClient(client)
    }
}
