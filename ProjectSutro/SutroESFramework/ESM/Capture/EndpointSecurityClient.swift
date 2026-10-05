//
//  EndpointSecurityClient.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import EndpointSecurity


// MARK: - Endpoint Security client
/// One Endpoint Security client, as a capture session drives it.
///
/// ``LiveEndpointSecurityClient`` calls EndpointSecurity. The tests use a fake that records each call and delivers
/// messages they build, since only root can create a real client.
///
/// **Threading:** a capture session makes every call on its own serial queue, so ``delete()`` never overlaps another
/// call on the same client, as `ESClient.h` requires.
protocol EndpointSecurityClient: AnyObject {
    /// Subscribe to more events (`es_subscribe`).
    ///
    /// - Parameter events: The events to add. An empty list succeeds without a call.
    /// - Returns: `true` if Endpoint Security accepted them.
    func subscribe(_ events: [es_event_type_t]) -> Bool
    
    /// Unsubscribe from some events (`es_unsubscribe`).
    ///
    /// - Parameter events: The events to drop. An empty list succeeds without a call.
    /// - Returns: `true` if Endpoint Security accepted the request.
    func unsubscribe(_ events: [es_event_type_t]) -> Bool
    
    /// Unsubscribe from every event (`es_unsubscribe_all`): Endpoint Security stops generating messages for the client.
    ///
    /// - Returns: `true` on success.
    func unsubscribeAll() -> Bool
    
    /// Suppress every event from a process, as submitter or instigator (`es_mute_process`).
    ///
    /// - Parameter token: The process's audit token. It must be running.
    /// - Returns: `true` on success.
    func muteProcess(_ token: audit_token_t) -> Bool
    
    /// Mute or unmute a path (`es_mute_path`, `es_mute_path_events`, and their unmute counterparts).
    ///
    /// - Parameters:
    ///   - mute: The path, its type, and the events to scope the request to (none for every event).
    ///   - muted: `true` to mute, `false` to unmute.
    /// - Returns: `true` if Endpoint Security accepted the request.
    func setPathMute(_ mute: PathMute, muted: Bool) -> Bool
    
    /// Every path muted on the client, Endpoint Security's own default mutes included (`es_muted_paths_events`).
    ///
    /// - Returns: The muted paths, or none if they can't be read.
    func mutedPaths() -> [ESMutedPath]
    
    /// Delete the client (`es_delete_client`). Calling it again does nothing.
    ///
    /// - Returns: `false` if Endpoint Security leaked the client's resources while tearing it down.
    @discardableResult
    func delete() -> Bool
}


// MARK: - Client factory
/// Why Endpoint Security refused a new client.
struct ClientRefusal: Error, Equatable {
    /// The refusal, as Mac Monitor reports `es_new_client`'s result.
    let result: NewClientResult
    
    /// - Parameter result: The refusal.
    init(result: NewClientResult) {
        self.result = result
    }
}


/// Makes Endpoint Security clients for a capture session.
protocol EndpointSecurityClientFactory {
    /// Create a client. It receives no messages until it subscribes.
    ///
    /// - Parameter handler: Called for each message, serially, on the new client's own queue. The message is only
    ///   valid during the call.
    /// - Returns: The client.
    /// - Throws: ``ClientRefusal`` when `es_new_client` refuses, such as when the system has too many clients.
    func makeClient(handler: @escaping (UnsafePointer<es_message_t>) -> Void) throws -> any EndpointSecurityClient
}
