//
//  ProfileAddEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/5/23.
//

import Foundation


/// Models a `ES_EVENT_TYPE_NOTIFY_PROFILE_ADD` which describes a profile being installed on the system.
///
/// https://developer.apple.com/documentation/endpointsecurity/3228936-es_events_t/4161242-profile_add
///
//@available(macOS, introduced: 14.0)
public struct ProfileAddEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var instigator: Process?
    public var is_update: Bool
    public var profile: Profile
    
    // Available in msg versions >= 8.
    public var instigator_token: AuditToken?
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_profile_add_t = rawMessage.pointee.event.profile_add.pointee
        let version: Int = Int(rawMessage.pointee.version)
        
        self.instigator = event.instigator.map { Process(from: $0.pointee, version: version) }
        
        self.is_update = event.is_update
        self.profile = Profile(from: event.profile.pointee)
        instigator_token = version >= 8 ? AuditToken(from: event.instigator_token) : nil
    }
}
