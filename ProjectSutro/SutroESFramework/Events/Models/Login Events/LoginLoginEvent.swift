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
    public var uid: Int64
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: LoginLoginEvent, rhs: LoginLoginEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let loginLoginEvent: es_event_login_login_t = rawMessage.pointee.event.login_login.pointee
    
        self.succcess = loginLoginEvent.success
        if !loginLoginEvent.success &&  loginLoginEvent.failure_message.length > 0 {
            self.failure_message = String(cString: loginLoginEvent.failure_message.data)
        }
        
        self.username = String(cString: loginLoginEvent.username.data)
        self.has_uid = loginLoginEvent.has_uid
        self.uid = loginLoginEvent.has_uid ? Int64(loginLoginEvent.uid.uid) : -1
        enrich()
        if loginLoginEvent.has_uid {
            self.uid_human = String(cString: getpwuid(uid_t(loginLoginEvent.uid.uid))!.pointee.pw_name)
        }
    }
}


// MARK: - Mac Monitor enrichment
extension LoginLoginEvent: ESEnrichable {
    /// Derive the user's name if it's a system account, or "Unknown" without a user ID.
    ///
    /// Not derived: the names of other users (read from this Mac).
    public mutating func enrich() {
        uid_human = has_uid ? Process.userName(Int(uid), systemAccountsOnly: true) ?? uid_human : "Unknown"
    }
}
