//
//  ActionResult.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/14/25.
//

import Foundation


/// Models an `action_type` union from an `es_message_t`
public struct ActionResult: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID.buffered()
    
    public var result_type: Int?
    public var result_type_human: String?
    public var result: AuthResult?
    
    // Ignore id from being decoded
    enum CodingKeys: String, CodingKey {
        case result_type, result_type_human, result
    }
    
    init(from message: es_message_t) {
        
        /// Switch on the action type
        switch message.action_type {
        /// The result is an auth result
        case ES_ACTION_TYPE_AUTH:
            /// `es_event_id_t` only contains a reserved field
            /// An opaque identifier for events.
            break
        /// The result is a flags result
        case ES_ACTION_TYPE_NOTIFY:
            self.result_type = Int(message.action.notify.result_type.rawValue)
            
            /// Switch on the result type: `es_result_type_t`
            switch message.action.notify.result_type {
            case ES_RESULT_TYPE_AUTH:
                self.result = AuthResult(from: message.action.notify.result.auth)
            case ES_RESULT_TYPE_FLAGS:
                self.result = AuthResult(from: message.action.notify.result.flags)
            default:
                break
            }
            enrich()
        default:
            break
        }
    }
}


// MARK: - Mac Monitor enrichment
extension ActionResult: ESEnrichable {
    /// Derive the result type's name.
    public mutating func enrich() {
        switch result_type.map({ es_result_type_t(rawValue: UInt32(truncatingIfNeeded: $0)) }) {
        case ES_RESULT_TYPE_AUTH: result_type_human = "ES_RESULT_TYPE_AUTH"
        case ES_RESULT_TYPE_FLAGS: result_type_human = "ES_RESULT_TYPE_FLAGS"
        default: break
        }
    }
}


public struct ActionResultWrapper: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID.buffered()
    
    public var result: ActionResult?
    
    // Ignore id from being decoded
    enum CodingKeys: String, CodingKey {
        case result
    }
    
    init(from message: es_message_t) {
        self.result = ActionResult(from: message)
    }
}
