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
public struct TCCModifyEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    public var service, identity: String
    public var identity_type_string = "", update_type_string = "", right_string = "", reason_string = ""
    public var identity_type, update_type, right, reason: UInt32
    public var instigator_token: AuditToken
    public var instigator, responsible: Process?
    public var responsible_token: AuditToken?
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let tccModifyEvent: es_event_tcc_modify_t = rawMessage.pointee.event.tcc_modify.pointee
        let version: Int = Int(rawMessage.pointee.version)
        
        service = tccModifyEvent.service.string ?? ""
        identity = tccModifyEvent.identity.string ?? ""
        identity_type = tccModifyEvent.identity_type.rawValue
        update_type = tccModifyEvent.update_type.rawValue
        instigator_token = AuditToken(from: tccModifyEvent.instigator_token)
        
        self.instigator = tccModifyEvent.instigator.map { Process(from: $0.pointee, version: version) }
        self.responsible_token = tccModifyEvent.responsible_token.map { AuditToken(from: $0.pointee) }
        self.responsible = tccModifyEvent.responsible.map { Process(from: $0.pointee, version: version) }
        
        right = tccModifyEvent.right.rawValue
        reason = tccModifyEvent.reason.rawValue
        
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension TCCModifyEvent: ESEnrichable {
    /// `es_tcc_identity_type_t`: what the identity is.
    private static let identityTypeNames = ConstantNames([
        ES_TCC_IDENTITY_TYPE_BUNDLE_ID.rawValue: "ES_TCC_IDENTITY_TYPE_BUNDLE_ID",
        ES_TCC_IDENTITY_TYPE_POLICY_ID.rawValue: "ES_TCC_IDENTITY_TYPE_POLICY_ID",
        ES_TCC_IDENTITY_TYPE_EXECUTABLE_PATH.rawValue: "ES_TCC_IDENTITY_TYPE_EXECUTABLE_PATH",
        ES_TCC_IDENTITY_TYPE_FILE_PROVIDER_DOMAIN_ID.rawValue: "ES_TCC_IDENTITY_TYPE_FILE_PROVIDER_DOMAIN_ID",
    ], unknown: "Unknown")
    
    /// `es_tcc_event_type_t`: how the right changed.
    private static let updateTypeNames = ConstantNames([
        ES_TCC_EVENT_TYPE_UNKNOWN.rawValue: "ES_TCC_EVENT_TYPE_UNKNOWN",
        ES_TCC_EVENT_TYPE_CREATE.rawValue: "ES_TCC_EVENT_TYPE_CREATE",
        ES_TCC_EVENT_TYPE_MODIFY.rawValue: "ES_TCC_EVENT_TYPE_MODIFY",
        ES_TCC_EVENT_TYPE_DELETE.rawValue: "ES_TCC_EVENT_TYPE_DELETE",
    ], unknown: "Unknown")
    
    /// `es_tcc_authorization_right_t`: what TCC decided.
    private static let rightNames = ConstantNames([
        ES_TCC_AUTHORIZATION_RIGHT_DENIED.rawValue: "ES_TCC_AUTHORIZATION_RIGHT_DENIED",
        ES_TCC_AUTHORIZATION_RIGHT_UNKNOWN.rawValue: "ES_TCC_AUTHORIZATION_RIGHT_UNKNOWN",
        ES_TCC_AUTHORIZATION_RIGHT_ALLOWED.rawValue: "ES_TCC_AUTHORIZATION_RIGHT_ALLOWED",
        ES_TCC_AUTHORIZATION_RIGHT_LIMITED.rawValue: "ES_TCC_AUTHORIZATION_RIGHT_LIMITED",
        ES_TCC_AUTHORIZATION_RIGHT_ADD_MODIFY_ADDED.rawValue: "ES_TCC_AUTHORIZATION_RIGHT_ADD_MODIFY_ADDED",
        ES_TCC_AUTHORIZATION_RIGHT_SESSION_PID.rawValue: "ES_TCC_AUTHORIZATION_RIGHT_SESSION_PID",
        ES_TCC_AUTHORIZATION_RIGHT_LEARN_MORE.rawValue: "ES_TCC_AUTHORIZATION_RIGHT_LEARN_MORE",
    ], unknown: "Unknown")
    
    /// `es_tcc_authorization_reason_t`: why TCC decided it.
    private static let reasonNames = ConstantNames([
        ES_TCC_AUTHORIZATION_REASON_NONE.rawValue: "ES_TCC_AUTHORIZATION_REASON_NONE",
        ES_TCC_AUTHORIZATION_REASON_ERROR.rawValue: "ES_TCC_AUTHORIZATION_REASON_ERROR",
        ES_TCC_AUTHORIZATION_REASON_USER_CONSENT.rawValue: "ES_TCC_AUTHORIZATION_REASON_USER_CONSENT",
        ES_TCC_AUTHORIZATION_REASON_USER_SET.rawValue: "ES_TCC_AUTHORIZATION_REASON_USER_SET",
        ES_TCC_AUTHORIZATION_REASON_SYSTEM_SET.rawValue: "ES_TCC_AUTHORIZATION_REASON_SYSTEM_SET",
        ES_TCC_AUTHORIZATION_REASON_SERVICE_POLICY.rawValue: "ES_TCC_AUTHORIZATION_REASON_SERVICE_POLICY",
        ES_TCC_AUTHORIZATION_REASON_MDM_POLICY.rawValue: "ES_TCC_AUTHORIZATION_REASON_MDM_POLICY",
        ES_TCC_AUTHORIZATION_REASON_SERVICE_OVERRIDE_POLICY.rawValue:
            "ES_TCC_AUTHORIZATION_REASON_SERVICE_OVERRIDE_POLICY",
        ES_TCC_AUTHORIZATION_REASON_MISSING_USAGE_STRING.rawValue: "ES_TCC_AUTHORIZATION_REASON_MISSING_USAGE_STRING",
        ES_TCC_AUTHORIZATION_REASON_PROMPT_TIMEOUT.rawValue: "ES_TCC_AUTHORIZATION_REASON_PROMPT_TIMEOUT",
        ES_TCC_AUTHORIZATION_REASON_PREFLIGHT_UNKNOWN.rawValue: "ES_TCC_AUTHORIZATION_REASON_PREFLIGHT_UNKNOWN",
        ES_TCC_AUTHORIZATION_REASON_ENTITLED.rawValue: "ES_TCC_AUTHORIZATION_REASON_ENTITLED",
        ES_TCC_AUTHORIZATION_REASON_APP_TYPE_POLICY.rawValue: "ES_TCC_AUTHORIZATION_REASON_APP_TYPE_POLICY",
        ES_TCC_AUTHORIZATION_REASON_PROMPT_CANCEL.rawValue: "ES_TCC_AUTHORIZATION_REASON_PROMPT_CANCEL",
    ], unknown: "Unknown")
    
    /// Derive the names of the identity type, update type, right, and reason.
    public mutating func enrich() {
        identity_type_string = Self.identityTypeNames.name(of: Int(identity_type))
        update_type_string = Self.updateTypeNames.name(of: Int(update_type))
        right_string = Self.rightNames.name(of: Int(right))
        reason_string = Self.reasonNames.name(of: Int(reason))
    }
}
