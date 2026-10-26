//
//  LWSessionEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


// MARK: - Endpoint Security's login window session events
/// The fields an `es_event_lw_session_login_t` and `es_event_lw_session_unlock_t` share.
protocol LWSessionFields {
    /// The user's short name.
    var username: es_string_token_t { get }
    /// The graphical session's ID.
    var graphical_session_id: es_graphical_session_id_t { get }
}

extension es_event_lw_session_login_t: LWSessionFields {}
extension es_event_lw_session_unlock_t: LWSessionFields {}


// MARK: - Login window session event
// https://developer.apple.com/documentation/endpointsecurity/es_event_lw_session_login_t
// https://developer.apple.com/documentation/endpointsecurity/es_event_lw_session_unlock_t
/// Models an `ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN` or `ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK`: a user logged in at
/// the login window, or unlocked their session.
public struct LWSessionEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()

    public var username: String
    public var graphical_session_id: Int32

    /// Record the event of a message from Endpoint Security.
    ///
    /// - Parameter event: The message's `lw_session_login` or `lw_session_unlock`.
    init(from event: some LWSessionFields) {
        username = event.username.string ?? ""
        /// A `uint32_t`, kept by bit pattern: one of 2^31 or more has no `Int32`.
        graphical_session_id = Int32(bitPattern: event.graphical_session_id)
    }
}
