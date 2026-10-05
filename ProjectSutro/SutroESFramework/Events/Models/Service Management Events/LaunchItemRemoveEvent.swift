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
public struct LaunchItemRemoveEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    public var instigator: Process?
    public var app: Process?
    public var item: LaunchItem
    
    /// Message `>= 8`:
    public var instigator_token, app_token: AuditToken?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: LaunchItemRemoveEvent, rhs: LaunchItemRemoveEvent) -> Bool {
        if lhs.id == rhs.id {
            return true
        }
        
        return false
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_btm_launch_item_remove_t = rawMessage.pointee.event.btm_launch_item_remove.pointee
        let version: Int = Int(rawMessage.pointee.version)
        
        // MARK: - Instigator & App
        if let eventInstigator = event.instigator {
            instigator = Process(from: eventInstigator.pointee, version: version)
        }
        
        if let eventApp = event.app {
            app = Process(from: eventApp.pointee, version: version)
        }
        
        if version >= 8 {
            if let instigatorToken = event.instigator_token {
                instigator_token = AuditToken(from: instigatorToken.pointee)
            }
            
            if let appToken = event.app_token {
                app_token = AuditToken(from: appToken.pointee)
            }
        }
        
        // MARK: - Item
        item = LaunchItem(from: event.item.pointee)
    }
}
