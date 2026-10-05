//
//  XProtectDetectEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//

import Foundation


// MARK: - XProtect Malware Detected event model: https://developer.apple.com/documentation/endpointsecurity/es_event_xp_malware_detected_t
public struct XProtectDetectEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    public var signature_version: String
    public var malware_identifier: String
    public var incident_identifier: String
    public var detected_path: String
    
    /* field available only if message version >= 10 */
    public var detected_executable: String?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: XProtectDetectEvent, rhs: XProtectDetectEvent) -> Bool {
        if lhs.id == rhs.id {
            return true
        }
        
        return false
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_xp_malware_detected_t = rawMessage.pointee.event.xp_malware_detected.pointee
        let version: Int = Int(rawMessage.pointee.version)
        
        self.signature_version = event.signature_version.string ?? ""
        self.malware_identifier = event.malware_identifier.string ?? ""
        self.incident_identifier = event.incident_identifier.string ?? ""
        self.detected_path = event.detected_path.string ?? ""
        
        if version >= 10 {
            self.detected_executable = event.detected_executable.string
        }
    }
}
