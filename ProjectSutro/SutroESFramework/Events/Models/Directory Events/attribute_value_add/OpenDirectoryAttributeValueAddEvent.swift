//
//  OpenDirectoryAttributeValueAddEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/28/23.
//
// ES documentation: `es_event_od_attribute_value_add_t`
/**
 * @brief Notification that an attribute value was added to a record.
 *
 * @field instigator       Process that instigated operation (XPC caller).
 * @field error_code       0 indicates the operation succeeded.
 *                         Values inidicating specific failure reasons are defined in odconstants.h.
 * @field record_type      The type of the record to which the attribute value was added.
 * @field record_name      The name of the record to which the attribute value was added.
 * @field attribute_name   The name of the attribute to which the value was added.
 * @field attribute_value  The value that was added.
 * @field node_name        OD node being mutated.
 *                         Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                         "/Active Directory/<domain>".
 * @field db_path          Optional.  If node_name is "/Local/Default", this is
 *                         the path of the database against which OD is
 *                         authenticating.
 *
 * @note This event type does not support caching (notify-only).
 * @note Attributes conceptually have the type `Map String (Set String)`.
 *       Each OD record has a Map of attribute name to Set of attribute value.
 *       When an attribute value is added, it is inserted into the set of values for that name.
 */

import Foundation


public struct OpenDirectoryAttributeValueAddEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    public var instigator_process_name, instigator_process_path, instigator_process_audit_token, instigator_process_signing_id: String?
    public var error_code: Int
    public var record_type: String
    public var record_name: String?
    public var attribute_name: String?
    public var attribute_value: String?
    public var node_name: String?
    public var db_path: String?
    public var error_code_human: String?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: OpenDirectoryAttributeValueAddEvent, rhs: OpenDirectoryAttributeValueAddEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let attributeValueAddEvent: es_event_od_attribute_value_add_t = rawMessage.pointee.event.od_attribute_value_add.pointee
        let instigatorProcess: es_process_t = attributeValueAddEvent.instigator!.pointee
        
        self.instigator_process_name = ""
        if instigatorProcess.executable.pointee.path.length > 0 {
            self.instigator_process_name = URL(fileURLWithPath: String(cString: instigatorProcess.executable.pointee.path.data)).lastPathComponent
        }
        
        self.instigator_process_path = ""
        if instigatorProcess.executable.pointee.path.length > 0 {
            self.instigator_process_path = String(cString: instigatorProcess.executable.pointee.path.data)
        }
        
        self.instigator_process_signing_id = ""
        if instigatorProcess.signing_id.length > 0 {
            self.instigator_process_signing_id = String(cString: instigatorProcess.signing_id.data)
        }
        
        self.instigator_process_audit_token = ""
        self.instigator_process_audit_token = instigatorProcess.audit_token
            .toString()
        
        self.error_code = Int(attributeValueAddEvent.error_code)
    
        self.record_type = ""
        switch(attributeValueAddEvent.record_type) {
        case ES_OD_RECORD_TYPE_USER:
            self.record_type = "USER"
            break
        case ES_OD_RECORD_TYPE_GROUP:
            self.record_type = "GROUP"
            break
        default:
            self.record_type = "UNKNOWN"
        }

        self.record_name = ""
        if attributeValueAddEvent.record_name.length > 0 {
            self.record_name = String(cString: attributeValueAddEvent.record_name.data)
        }
        
        self.attribute_name = ""
        if attributeValueAddEvent.attribute_name.length > 0 {
            self.attribute_name = String(cString: attributeValueAddEvent.attribute_name.data)
        }

        self.attribute_value = ""
        if attributeValueAddEvent.attribute_value.length > 0 {
            self.attribute_value = String(cString: attributeValueAddEvent.attribute_value.data)
        }
        
        self.node_name = ""
        if attributeValueAddEvent.node_name.length > 0 {
            self.node_name = String(cString: attributeValueAddEvent.node_name.data)
        }
        
        self.db_path = ""
        if attributeValueAddEvent.db_path.length > 0 {
            self.db_path = String(cString: attributeValueAddEvent.db_path.data)
        }
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension OpenDirectoryAttributeValueAddEvent: ESEnrichable {
    /// Derive the error code's description.
    public mutating func enrich() {
        error_code_human = decodeODErrorCode(error_code)
    }
}
