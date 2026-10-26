//
//  LaunchItemRemoveEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//

import Foundation
import EndpointSecurity
import OSLog
//import SwiftCSBlobs
import Compression
import Security
import CryptoKit


// MARK: - Background Task Management (BTM) Launch Item Remove event model https://developer.apple.com/documentation/endpointsecurity/3228936-es_events_t/4042929-btm_launch_item_remove
public struct LaunchItemRemoveEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var instigator: Process?
    public var app: Process?
    public var item: LaunchItem
    
    /// Message `>= 8`:
    public var instigator_token, app_token: AuditToken?
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_btm_launch_item_remove_t = rawMessage.pointee.event.btm_launch_item_remove.pointee
        let version: Int = Int(rawMessage.pointee.version)
        
        // MARK: - Instigator & App
        instigator = event.instigator.map { Process(from: $0.pointee, version: version) }
        app = event.app.map { Process(from: $0.pointee, version: version) }
        
        if version >= 8 {
            instigator_token = event.instigator_token.map { AuditToken(from: $0.pointee) }
            app_token = event.app_token.map { AuditToken(from: $0.pointee) }
        }
        
        // MARK: - Item
        item = LaunchItem(from: event.item.pointee)
    }
}
