//
//  LoginLoginEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/17/23.
//

import Foundation
import EndpointSecurity
import OSLog


// https://developer.apple.com/documentation/endpointsecurity/es_event_login_login_t
public struct LoginLoginEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var succcess, has_uid: Bool
    public var username: String
    public var uid_human = ""
    public var failure_message: String?
    /// The user's ID: `nil` (eslogger's `null`) without one.
    public var uid: Int64?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: LoginLoginEvent, rhs: LoginLoginEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let loginLoginEvent: es_event_login_login_t = rawMessage.pointee.event.login_login.pointee
    
        self.succcess = loginLoginEvent.success
        /// Optional: `nil` (eslogger's `null`) without one. Read whatever `success` says, as eslogger reads it.
        self.failure_message = loginLoginEvent.failure_message.string
        
        self.username = loginLoginEvent.username.string ?? ""
        self.has_uid = loginLoginEvent.has_uid
        self.uid = loginLoginEvent.has_uid ? Int64(loginLoginEvent.uid.uid) : nil
        enrich()
        /// Any user this Mac knows. A uid it doesn't (a directory user while the directory is offline, a deleted
        /// account) keeps the name ``enrich()`` gave it.
        if let uid, let name = Process.userName(Int(uid), systemAccountsOnly: false) {
            self.uid_human = name
        }
    }
}


// MARK: - Mac Monitor enrichment
extension LoginLoginEvent: ESEnrichable {
    /// Derive `has_uid`, which eslogger doesn't write (there's a uid exactly when it's set), and the user's name if
    /// it's a system account, or "Unknown" without a user ID.
    ///
    /// Not derived: the names of other users (read from this Mac).
    public mutating func enrich() {
        has_uid = uid != nil
        uid_human = uid.map { Process.userName(Int($0), systemAccountsOnly: true) ?? uid_human } ?? "Unknown"
    }
}
