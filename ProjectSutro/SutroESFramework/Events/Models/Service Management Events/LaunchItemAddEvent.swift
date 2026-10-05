//
//  LaunchItemAddEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//

import Foundation


// MARK: - Background Task Management (BTM) Launch Item Add event model https://developer.apple.com/documentation/endpointsecurity/3228936-es_events_t/4042928-btm_launch_item_add
public struct LaunchItemAddEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var instigator: Process?
    public var app: Process?
    public var item: LaunchItem
    /// Optional ("if available and applicable"): `nil`, eslogger's `null`, when it isn't.
    public var executable_path: String?
    
    /// Message `>= 8`:
    public var instigator_token, app_token: AuditToken?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: LaunchItemAddEvent, rhs: LaunchItemAddEvent) -> Bool {
        if lhs.id == rhs.id {
            return true
        }
        
        return false
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let lauchItemAddEvent: es_event_btm_launch_item_add_t = rawMessage.pointee.event.btm_launch_item_add.pointee
        let version: Int = Int(rawMessage.pointee.version)
        
        // MARK: - Instigator & App
        if let eventInstigator = lauchItemAddEvent.instigator {
            instigator = Process(from: eventInstigator.pointee, version: version)
        }
        
        if let eventApp = lauchItemAddEvent.app {
            app = Process(from: eventApp.pointee, version: version)
        }
        
        if version >= 8 {
            if let instigatorToken = lauchItemAddEvent.instigator_token {
                instigator_token = AuditToken(from: instigatorToken.pointee)
            }
            
            if let appToken = lauchItemAddEvent.app_token {
                app_token = AuditToken(from: appToken.pointee)
            }
        }
        
        // MARK: - Item
        item = LaunchItem(from: lauchItemAddEvent.item.pointee)
        
        // MARK: - Executable path
        executable_path = lauchItemAddEvent.executable_path.string
    }
}
