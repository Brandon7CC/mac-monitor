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
    
    /// eslogger's keys, then Mac Monitor's.
    enum CodingKeys: String, CodingKey {
        case id, statfs, disposition, disposition_string
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: MountEvent, rhs: MountEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_mount_t = rawMessage.pointee.event.mount
        
        statfs = StatFS(from: event.statfs.pointee)
        
        /// Message version 8 and later. Before it the field is reserved: its zeros would read as an external device.
        let disposition = rawMessage.pointee.version >= 8 ? event.disposition : ES_MOUNT_DISPOSITION_UNKNOWN
        self.disposition = Int16(truncatingIfNeeded: disposition.rawValue)
        enrich()
    }
}


// MARK: - Decoding
extension MountEvent {
    /// Read the event from eslogger's JSON, an export, or the Security Extension. eslogger's traces before message
    /// version 8 have no `disposition`, which reads as unknown, as the Security Extension records it for those
    /// versions: a default of 0 would read as an external device.
    ///
    /// - Parameter decoder: The event's decoder.
    /// - Throws: The error decoding a field, such as a `statfs` that isn't an object.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        statfs = try container.decode(StatFS.self, forKey: .statfs)
        disposition = try container.decodeIfPresent(Int16.self, forKey: .disposition)
            ?? Int16(truncatingIfNeeded: ES_MOUNT_DISPOSITION_UNKNOWN.rawValue)
        disposition_string = try container.decodeIfPresent(String.self, forKey: .disposition_string) ?? ""
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
