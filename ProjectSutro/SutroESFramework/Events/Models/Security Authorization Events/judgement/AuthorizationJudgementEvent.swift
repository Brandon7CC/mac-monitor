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
    
    public var ruleClassShortName: String { rule_class_string.droppingPrefix("ES_AUTHORIZATION_RULE_CLASS_") }
    
    public var description: String {
        return "Right name: \(self.ruleClassShortName), Rule class: \(rule_class), Granted: \(granted)"
    }

    /// `es_authorization_rule_class_t`: how the right is judged (on user properties, by a tree of sub-rules or by
    /// one or more plugins), or whether it's always granted or denied.
    private static let ruleClassNames = ConstantNames([
        ES_AUTHORIZATION_RULE_CLASS_USER.rawValue: "ES_AUTHORIZATION_RULE_CLASS_USER",
        ES_AUTHORIZATION_RULE_CLASS_RULE.rawValue: "ES_AUTHORIZATION_RULE_CLASS_RULE",
        ES_AUTHORIZATION_RULE_CLASS_MECHANISM.rawValue: "ES_AUTHORIZATION_RULE_CLASS_MECHANISM",
        ES_AUTHORIZATION_RULE_CLASS_ALLOW.rawValue: "ES_AUTHORIZATION_RULE_CLASS_ALLOW",
        ES_AUTHORIZATION_RULE_CLASS_DENY.rawValue: "ES_AUTHORIZATION_RULE_CLASS_DENY",
        ES_AUTHORIZATION_RULE_CLASS_UNKNOWN.rawValue: "ES_AUTHORIZATION_RULE_CLASS_UNKNOWN",
        ES_AUTHORIZATION_RULE_CLASS_INVALID.rawValue: "ES_AUTHORIZATION_RULE_CLASS_INVALID",
    ])
    
    init(from esResult: es_authorization_result_t) {
        right_name = esResult.right_name.string ?? ""
        granted = esResult.granted
        rule_class = Int32(esResult.rule_class.rawValue)
        
        rule_class_string = Self.ruleClassNames.name(of: Int(rule_class))
    }
}



public struct AuthorizationJudgementEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var instigator, petitioner: Process?
    
    public var results: [ESAuthorizationResult] = []
    
    public var return_code: Int32
    public var result_count: Int32
    
    // Available in msg versions >= 8.
    public var instigator_token, petitioner_token: AuditToken?
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_authorization_judgement_t = rawMessage.pointee.event.authorization_judgement.pointee
        let version: Int = Int(rawMessage.pointee.version)
        
        return_code = Int32(event.return_code)
        result_count = Int32(event.result_count)
        
        self.instigator = event.instigator.map { Process(from: $0.pointee, version: version) }
        self.petitioner = event.petitioner.map { Process(from: $0.pointee, version: version) }
        
        /// Read whether or not Endpoint Security gave the processes, which are `_Nullable`.
        instigator_token = version >= 8 ? AuditToken(from: event.instigator_token) : nil
        petitioner_token = version >= 8 ? AuditToken(from: event.petitioner_token) : nil
        
        if let rawResults = event.results {
            let esResults = (0..<event.result_count).map { index in
                return ESAuthorizationResult(from: rawResults[index])
            }
            self.results = esResults
        }
    }
}
