//
//  ProcessCheckEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/3/23.
//

import Foundation


/**
 * @brief Access control check for retrieving process information.
 *
 * @field target The process for which the access will be checked
 * @field type The type of call number used to check the access on the target process
 * @field flavor The flavor used to check the access on the target process
 *
 * @note Cache key for this event type:  (process executable file, target process executable file, type)
 */
// MARK: - Process check https://developer.apple.com/documentation/endpointsecurity/es_event_proc_check_t
public struct ProcessCheckEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    public var target: Process?
    public var type: Int32
    public var type_string = ""
    public var flavor: Int
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: ProcessCheckEvent, rhs: ProcessCheckEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let procCheckEvent: es_event_proc_check_t = rawMessage.pointee.event.proc_check
        
        if let target = procCheckEvent.target {
            self.target = Process(from: target.pointee, version: Int(rawMessage.pointee.version))
        }
        
        self.flavor = Int(procCheckEvent.flavor)
        
        self.type = Int32(procCheckEvent.type.rawValue)
        
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension ProcessCheckEvent: ESEnrichable {
    /// Derive the check type's name.
    public mutating func enrich() {
        switch es_proc_check_type_t(rawValue: UInt32(truncatingIfNeeded: type)) {
        case ES_PROC_CHECK_TYPE_PIDINFO:
            self.type_string = "ES_PROC_CHECK_TYPE_PIDINFO"
        case ES_PROC_CHECK_TYPE_LISTPIDS:
            self.type_string = "ES_PROC_CHECK_TYPE_LISTPIDS"
        case ES_PROC_CHECK_TYPE_PIDFDINFO:
            self.type_string = "ES_PROC_CHECK_TYPE_PIDFDINFO"
        case ES_PROC_CHECK_TYPE_PIDRUSAGE:
            self.type_string = "ES_PROC_CHECK_TYPE_PIDRUSAGE"
        case ES_PROC_CHECK_TYPE_TERMINATE:
            self.type_string = "ES_PROC_CHECK_TYPE_TERMINATE"
        case ES_PROC_CHECK_TYPE_KERNMSGBUF:
            self.type_string = "ES_PROC_CHECK_TYPE_KERNMSGBUF"
        case ES_PROC_CHECK_TYPE_SETCONTROL:
            self.type_string = "ES_PROC_CHECK_TYPE_SETCONTROL"
        case ES_PROC_CHECK_TYPE_DIRTYCONTROL:
            self.type_string = "ES_PROC_CHECK_TYPE_DIRTYCONTROL"
        case ES_PROC_CHECK_TYPE_PIDFILEPORTINFO:
            self.type_string = "ES_PROC_CHECK_TYPE_PIDFILEPORTINFO"
        case ES_PROC_CHECK_TYPE_UDATA_INFO:
            self.type_string = "ES_PROC_CHECK_TYPE_UDATA_INFO"
        case ES_PROC_CHECK_TYPE_PIDFILEPORTINFO:
            self.type_string = "ES_PROC_CHECK_TYPE_PIDFILEPORTINFO"
        default:
            self.type_string = "UNKNOWN"
        }
    }
}
