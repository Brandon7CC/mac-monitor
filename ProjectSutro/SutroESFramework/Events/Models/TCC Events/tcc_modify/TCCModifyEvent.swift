//
//  TCCModifyEvent.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/15/25.
//

import Foundation
import EndpointSecurity


// MARK: - TCC Modify event model: https://developer.apple.com/documentation/endpointsecurity/es_event_tcc_modify_t
// Available beginning in macOS 15.4
public struct TCCModifyEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    public var service, identity: String
    public var identity_type_string = "", update_type_string = "", right_string = "", reason_string = ""
    public var identity_type, update_type, right, reason: UInt32
    public var instigator_token: AuditToken
    public var instigator, responsible: Process?
    public var responsible_token: AuditToken?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(instigator_token)
        hasher.combine(id)
    }
    
    public static func == (lhs: TCCModifyEvent, rhs: TCCModifyEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let tccModifyEvent: es_event_tcc_modify_t = rawMessage.pointee.event.tcc_modify.pointee
        let version: Int = Int(rawMessage.pointee.version)
        
        service = tccModifyEvent.service.string ?? ""
        identity = tccModifyEvent.identity.string ?? ""
        identity_type = tccModifyEvent.identity_type.rawValue
        update_type = tccModifyEvent.update_type.rawValue
        instigator_token = AuditToken(from: tccModifyEvent.instigator_token)
        
        if let instigator = tccModifyEvent.instigator {
            self.instigator = Process(from: instigator.pointee, version: version)
        }
        
        if let responsible_token = tccModifyEvent.responsible_token {
            self.responsible_token = AuditToken(from: responsible_token.pointee)
        }
        
        if let responsible = tccModifyEvent.responsible {
            self.responsible = Process(from: responsible.pointee, version: version)
        }
        
        right = tccModifyEvent.right.rawValue
        reason = tccModifyEvent.reason.rawValue
        
        // MARK: - Enrichment
        
        
        
        
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension TCCModifyEvent: ESEnrichable {
    /// Derive the names of the identity type, update type, right, and reason.
    public mutating func enrich() {
        switch es_tcc_identity_type_t(rawValue: identity_type) {
        case ES_TCC_IDENTITY_TYPE_BUNDLE_ID:
            identity_type_string = "ES_TCC_IDENTITY_TYPE_BUNDLE_ID"
        case ES_TCC_IDENTITY_TYPE_POLICY_ID:
            identity_type_string = "ES_TCC_IDENTITY_TYPE_POLICY_ID"
        case ES_TCC_IDENTITY_TYPE_EXECUTABLE_PATH:
            identity_type_string = "ES_TCC_IDENTITY_TYPE_EXECUTABLE_PATH"
        case ES_TCC_IDENTITY_TYPE_FILE_PROVIDER_DOMAIN_ID:
            identity_type_string = "ES_TCC_IDENTITY_TYPE_FILE_PROVIDER_DOMAIN_ID"
        default:
            identity_type_string = "Unknown"
        }
        switch es_tcc_event_type_t(rawValue: update_type) {
        case ES_TCC_EVENT_TYPE_UNKNOWN:
            update_type_string = "ES_TCC_EVENT_TYPE_UNKNOWN"
        case ES_TCC_EVENT_TYPE_CREATE:
            update_type_string = "ES_TCC_EVENT_TYPE_CREATE"
        case ES_TCC_EVENT_TYPE_MODIFY:
            update_type_string = "ES_TCC_EVENT_TYPE_MODIFY"
        case ES_TCC_EVENT_TYPE_DELETE:
            update_type_string = "ES_TCC_EVENT_TYPE_DELETE"
        default:
            update_type_string = "Unknown"
        }
        switch es_tcc_authorization_right_t(rawValue: right) {
        case ES_TCC_AUTHORIZATION_RIGHT_DENIED:
            right_string = "ES_TCC_AUTHORIZATION_RIGHT_DENIED"
        case ES_TCC_AUTHORIZATION_RIGHT_UNKNOWN:
            right_string = "ES_TCC_AUTHORIZATION_RIGHT_UNKNOWN"
        case ES_TCC_AUTHORIZATION_RIGHT_ALLOWED:
            right_string = "ES_TCC_AUTHORIZATION_RIGHT_ALLOWED"
        case ES_TCC_AUTHORIZATION_RIGHT_LIMITED:
            right_string = "ES_TCC_AUTHORIZATION_RIGHT_LIMITED"
        case ES_TCC_AUTHORIZATION_RIGHT_ADD_MODIFY_ADDED:
            right_string = "ES_TCC_AUTHORIZATION_RIGHT_ADD_MODIFY_ADDED"
        case ES_TCC_AUTHORIZATION_RIGHT_SESSION_PID:
            right_string = "ES_TCC_AUTHORIZATION_RIGHT_SESSION_PID"
        case ES_TCC_AUTHORIZATION_RIGHT_LEARN_MORE:
            right_string = "ES_TCC_AUTHORIZATION_RIGHT_LEARN_MORE"
        default:
            right_string = "Unknown"
        }
        switch es_tcc_authorization_reason_t(rawValue: reason) {
        case ES_TCC_AUTHORIZATION_REASON_NONE:
            reason_string = "ES_TCC_AUTHORIZATION_REASON_NONE"
        case ES_TCC_AUTHORIZATION_REASON_ERROR:
            reason_string = "ES_TCC_AUTHORIZATION_REASON_ERROR"
        case ES_TCC_AUTHORIZATION_REASON_USER_CONSENT:
            reason_string = "ES_TCC_AUTHORIZATION_REASON_USER_CONSENT"
        case ES_TCC_AUTHORIZATION_REASON_USER_SET:
            reason_string = "ES_TCC_AUTHORIZATION_REASON_USER_SET"
        case ES_TCC_AUTHORIZATION_REASON_SYSTEM_SET:
            reason_string = "ES_TCC_AUTHORIZATION_REASON_SYSTEM_SET"
        case ES_TCC_AUTHORIZATION_REASON_SERVICE_POLICY:
            reason_string = "ES_TCC_AUTHORIZATION_REASON_SERVICE_POLICY"
        case ES_TCC_AUTHORIZATION_REASON_MDM_POLICY:
            reason_string = "ES_TCC_AUTHORIZATION_REASON_MDM_POLICY"
        case ES_TCC_AUTHORIZATION_REASON_SERVICE_OVERRIDE_POLICY:
            reason_string = "ES_TCC_AUTHORIZATION_REASON_SERVICE_OVERRIDE_POLICY"
        case ES_TCC_AUTHORIZATION_REASON_MISSING_USAGE_STRING:
            reason_string = "ES_TCC_AUTHORIZATION_REASON_MISSING_USAGE_STRING"
        case ES_TCC_AUTHORIZATION_REASON_PROMPT_TIMEOUT:
            reason_string = "ES_TCC_AUTHORIZATION_REASON_PROMPT_TIMEOUT"
        case ES_TCC_AUTHORIZATION_REASON_PREFLIGHT_UNKNOWN:
            reason_string = "ES_TCC_AUTHORIZATION_REASON_PREFLIGHT_UNKNOWN"
        case ES_TCC_AUTHORIZATION_REASON_ENTITLED:
            reason_string = "ES_TCC_AUTHORIZATION_REASON_ENTITLED"
        case ES_TCC_AUTHORIZATION_REASON_APP_TYPE_POLICY:
            reason_string = "ES_TCC_AUTHORIZATION_REASON_APP_TYPE_POLICY"
        case ES_TCC_AUTHORIZATION_REASON_PROMPT_CANCEL:
            reason_string = "ES_TCC_AUTHORIZATION_REASON_PROMPT_CANCEL"
        default:
            reason_string = "Unknown"
        }
    }
}
