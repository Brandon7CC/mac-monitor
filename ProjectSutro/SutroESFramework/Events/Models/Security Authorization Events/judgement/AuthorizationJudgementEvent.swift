//
//  AuthorizationJudgementEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/28/23.
//

import Foundation


/**
 * @brief Describes, for a single right, the class of that right and if it was granted
 *
 * @field right_name            The name of the right being considered
 * @field rule_class            The class of the right being considered
 *                              The rule class determines how the operating system determines
 *                              if it should be granted or not
 * @field granted               Indicates if the right was granted or not
 */
public struct ESAuthorizationResult: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    /*
     * The class of rules used to evaluate the petition for a specific authorization right
     */
    public var rule_class: Int32
    public var rule_class_string: String
    public var right_name: String
    public var granted: Bool
    
    public var ruleClassShortName: String {
        return rule_class_string.replacingOccurrences(of: "ES_AUTHORIZATION_RULE_CLASS_", with: "")
    }
    
    public var description: String {
        return "Right name: \(self.ruleClassShortName), Rule class: \(rule_class), Granted: \(granted)"
    }

    init(from esResult: es_authorization_result_t) {
        right_name = esResult.right_name.string ?? ""
        granted = esResult.granted
        rule_class = Int32(esResult.rule_class.rawValue)
        
        switch esResult.rule_class {
        case ES_AUTHORIZATION_RULE_CLASS_USER:
            /// Right is judged on user properties
            rule_class_string = "ES_AUTHORIZATION_RULE_CLASS_USER"
        case ES_AUTHORIZATION_RULE_CLASS_RULE:
            /// Right is judged by a tree of sub-rules
            rule_class_string = "ES_AUTHORIZATION_RULE_CLASS_RULE"
        case ES_AUTHORIZATION_RULE_CLASS_MECHANISM:
            /// Right is judged by one or more plugins
            rule_class_string = "ES_AUTHORIZATION_RULE_CLASS_MECHANISM"
        case ES_AUTHORIZATION_RULE_CLASS_ALLOW:
            /// Right is always granted
            rule_class_string = "ES_AUTHORIZATION_RULE_CLASS_ALLOW"
        case ES_AUTHORIZATION_RULE_CLASS_DENY:
            /// Right is always denied
            rule_class_string = "ES_AUTHORIZATION_RULE_CLASS_DENY"
        case ES_AUTHORIZATION_RULE_CLASS_UNKNOWN:
            /// Right is unknown
            rule_class_string = "ES_AUTHORIZATION_RULE_CLASS_UNKNOWN"
        case ES_AUTHORIZATION_RULE_CLASS_INVALID:
            /// Right is invalid
            rule_class_string = "ES_AUTHORIZATION_RULE_CLASS_INVALID"
        default:
            rule_class_string = "UNKNOWN"
        }
    }
}



public struct AuthorizationJudgementEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    public var instigator, petitioner: Process?
    
    public var results: [ESAuthorizationResult] = []
    
    public var return_code: Int32
    public var result_count: Int32
    
    // Available in msg versions >= 8.
    public var instigator_token, petitioner_token: AuditToken?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: AuthorizationJudgementEvent, rhs: AuthorizationJudgementEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_authorization_judgement_t = rawMessage.pointee.event.authorization_judgement.pointee
        let version: Int = Int(rawMessage.pointee.version)
        
        return_code = Int32(event.return_code)
        result_count = Int32(event.result_count)
        
        if let instigator = event.instigator {
            self.instigator = Process(from: instigator.pointee, version: version)
        }
        
        if let petitioner = event.petitioner {
            self.petitioner = Process(from: petitioner.pointee, version: version)
        }
        
        /// Read whether or not Endpoint Security gave the processes, which are `_Nullable`.
        if version >= 8 {
            self.instigator_token = AuditToken(from: event.instigator_token)
            self.petitioner_token = AuditToken(from: event.petitioner_token)
        }
        
        if let rawResults = event.results {
            let esResults = (0..<event.result_count).map { index in
                return ESAuthorizationResult(from: rawResults[index])
            }
            self.results = esResults
        }
    }
}
