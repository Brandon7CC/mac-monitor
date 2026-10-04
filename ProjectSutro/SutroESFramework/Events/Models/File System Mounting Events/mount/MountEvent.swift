//
//  MountEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/17/23.
//

import Foundation


func charPointerToString(_ pointer: UnsafePointer<Int8>) -> String {
   return String(cString: UnsafeRawPointer(pointer).assumingMemoryBound(to: CChar.self))
}


// https://developer.apple.com/documentation/endpointsecurity/es_event_mount_t
public struct MountEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var statfs: StatFS
    public var disposition: Int16
    public var disposition_string = ""
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: MountEvent, rhs: MountEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_mount_t = rawMessage.pointee.event.mount
        
        statfs = StatFS(from: event.statfs.pointee)
        
        disposition = Int16(event.disposition.rawValue)
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension MountEvent: ESEnrichable {
    /// Derive the mount disposition's name.
    public mutating func enrich() {
        switch es_mount_disposition_t(rawValue: UInt32(truncatingIfNeeded: disposition)) {
        case ES_MOUNT_DISPOSITION_NULLFS:
            disposition_string = "ES_MOUNT_DISPOSITION_NULLFS"
        case ES_MOUNT_DISPOSITION_NETWORK:
            disposition_string = "ES_MOUNT_DISPOSITION_NETWORK"
        case ES_MOUNT_DISPOSITION_UNKNOWN:
            disposition_string = "ES_MOUNT_DISPOSITION_UNKNOWN"
        case ES_MOUNT_DISPOSITION_VIRTUAL:
            disposition_string = "ES_MOUNT_DISPOSITION_VIRTUAL"
        case ES_MOUNT_DISPOSITION_EXTERNAL:
            disposition_string = "ES_MOUNT_DISPOSITION_EXTERNAL"
        case ES_MOUNT_DISPOSITION_INTERNAL:
            disposition_string = "ES_MOUNT_DISPOSITION_INTERNAL"
        default:
            disposition_string = "UNKNOWN"
        }
    }
}
