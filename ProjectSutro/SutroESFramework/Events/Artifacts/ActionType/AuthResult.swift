//
//  AuthResult.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/14/25.
//

import Foundation

/// Models an `es_auth_result_t`
public struct AuthResult: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID()
    
    public var auth: Int?
    public var auth_human: String?
    public var flags: Int64?
    
    // Ignore id from being decoded
    enum CodingKeys: String, CodingKey {
        case auth, auth_human
        case flags
    }
    
    // When the action result type is `AUTH`
    init(from authResult: es_auth_result_t) {
        self.auth = Int(authResult.rawValue)
        enrich()
    }
    
    // When the action result type is `FLAGS`
    init(from flags: UInt32) {
        self.flags = Int64(flags)
    }
}


// MARK: - Mac Monitor enrichment
extension AuthResult: ESEnrichable {
    /// Derive the auth result's name.
    public mutating func enrich() {
        guard let auth else { return }
        switch es_auth_result_t(rawValue: UInt32(truncatingIfNeeded: auth)) {
        case ES_AUTH_RESULT_ALLOW:
            self.auth_human = "ES_AUTH_RESULT_ALLOW"
        case ES_AUTH_RESULT_DENY:
            self.auth_human = "ES_AUTH_RESULT_DENY"
        default:
            self.auth_human = "UNKNOWN_RESULT"
        }
    }
}
