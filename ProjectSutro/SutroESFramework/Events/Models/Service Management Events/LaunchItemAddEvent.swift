//
//  LaunchItemAddEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//

import Foundation


// MARK: - Background Task Management (BTM) Launch Item Add event model https://developer.apple.com/documentation/endpointsecurity/3228936-es_events_t/4042928-btm_launch_item_add
public struct LaunchItemAddEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var instigator: Process?
    public var app: Process?
    public var item: LaunchItem
    /// Optional ("if available and applicable"): `nil`, eslogger's `null`, when it isn't.
    public var executable_path: String?
    
    /// Message `>= 8`:
    public var instigator_token, app_token: AuditToken?
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let lauchItemAddEvent: es_event_btm_launch_item_add_t = rawMessage.pointee.event.btm_launch_item_add.pointee
        let version: Int = Int(rawMessage.pointee.version)
        
        // MARK: - Instigator & App
        instigator = lauchItemAddEvent.instigator.map { Process(from: $0.pointee, version: version) }
        app = lauchItemAddEvent.app.map { Process(from: $0.pointee, version: version) }
        
        instigator_token = version >= 8 ? lauchItemAddEvent.instigator_token.map { AuditToken(from: $0.pointee) } : nil
        app_token = version >= 8 ? lauchItemAddEvent.app_token.map { AuditToken(from: $0.pointee) } : nil
        
        // MARK: - Item
        item = LaunchItem(from: lauchItemAddEvent.item.pointee)
        
        // MARK: - Executable path
        executable_path = lauchItemAddEvent.executable_path.string
    }
}
