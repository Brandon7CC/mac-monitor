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
public struct ProcessCheckEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    public var target: Process?
    public var type: Int32
    public var type_string = ""
    public var flavor: Int
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let procCheckEvent: es_event_proc_check_t = rawMessage.pointee.event.proc_check
        
        self.target = procCheckEvent.target.map { Process(from: $0.pointee, version: Int(rawMessage.pointee.version)) }
        
        self.flavor = Int(procCheckEvent.flavor)
        
        self.type = Int32(procCheckEvent.type.rawValue)
        
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension ProcessCheckEvent: ESEnrichable {
    /// `es_proc_check_type_t`: the call that checks the target.
    private static let typeNames = ConstantNames([
        ES_PROC_CHECK_TYPE_PIDINFO.rawValue: "ES_PROC_CHECK_TYPE_PIDINFO",
        ES_PROC_CHECK_TYPE_LISTPIDS.rawValue: "ES_PROC_CHECK_TYPE_LISTPIDS",
        ES_PROC_CHECK_TYPE_PIDFDINFO.rawValue: "ES_PROC_CHECK_TYPE_PIDFDINFO",
        ES_PROC_CHECK_TYPE_PIDRUSAGE.rawValue: "ES_PROC_CHECK_TYPE_PIDRUSAGE",
        ES_PROC_CHECK_TYPE_TERMINATE.rawValue: "ES_PROC_CHECK_TYPE_TERMINATE",
        ES_PROC_CHECK_TYPE_KERNMSGBUF.rawValue: "ES_PROC_CHECK_TYPE_KERNMSGBUF",
        ES_PROC_CHECK_TYPE_SETCONTROL.rawValue: "ES_PROC_CHECK_TYPE_SETCONTROL",
        ES_PROC_CHECK_TYPE_DIRTYCONTROL.rawValue: "ES_PROC_CHECK_TYPE_DIRTYCONTROL",
        ES_PROC_CHECK_TYPE_PIDFILEPORTINFO.rawValue: "ES_PROC_CHECK_TYPE_PIDFILEPORTINFO",
        ES_PROC_CHECK_TYPE_UDATA_INFO.rawValue: "ES_PROC_CHECK_TYPE_UDATA_INFO",
    ])
    
    /// Derive the check type's name.
    public mutating func enrich() {
        type_string = Self.typeNames.name(of: Int(type))
    }
}
