//
//  AuthorizationPetitionEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/27/23.
//
//
// MARK: ES documentation reference `es_event_authorization_petition_t`
/**
 * @brief Notification that a process peititioned for certain authorization rights
 *
 * @field instigator            Process that submitted the petition (XPC caller)
 * @field petitioner            Process that created the petition
 * @field flags                 Flags associated with the petition. Defined Security framework "Authorization/Authorizatioh.h"
 * @field right_count           The number of elements in `rights`
 * @field rights                Array of string tokens, each token is the name of a right being requested
 *
 * @note This event type does not support caching (notify-only).
 */

import Foundation


public struct AuthorizationPetitionEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var instigator, petitioner: Process?
    public var flags: Int64
    public var flags_array: [String] = []
    public var right_count: Int32
    public var rights: [String]
    
    // Available in msg versions >= 8.
    public var instigator_token, petitioner_token: AuditToken?
    
    // Authorization flag map
    // Flags associated with the petition. Defined Security framework `Authorization/Authorization.h`
    /*!
        @typedef AuthorizationFlags
        Optional flags passed in to several Authorization APIs.
        See the description of AuthorizationCreate, AuthorizationCopyRights and AuthorizationFree for a description of how they affect those calls.
    */
    var authorizationFlags: [UInt32: String] = [
        0: "kAuthorizationFlagDefaults",
        1 << 0: "kAuthorizationFlagInteractionAllowed",
        1 << 1: "kAuthorizationFlagExtendRights",
        1 << 2: "kAuthorizationFlagPartialRights",
        1 << 3: "kAuthorizationFlagDestroyRights",
        1 << 4: "kAuthorizationFlagPreAuthorize",
        1 << 20: "kAuthorizationFlagNoData"
    ]
    
    // Function to translate flags to their string representation
    private func translateFlags(_ rawFlags: UInt32) -> [String] {
        var result = [String]()
        for (flagValue, flagString) in authorizationFlags {
            if rawFlags & flagValue != 0 {
                result.append(flagString)
            }
        }
        return result
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: AuthorizationPetitionEvent, rhs: AuthorizationPetitionEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_authorization_petition_t = rawMessage.pointee.event.authorization_petition.pointee
        let version: Int = Int(rawMessage.pointee.version)
        
        if let instigator = event.instigator {
            self.instigator = Process(from: instigator.pointee, version: version)
        }
        
        if let petitioner = event.petitioner {
            self.petitioner = Process(from: petitioner.pointee, version: version)
        }
        
        if version >= 8 {
            self.instigator_token = AuditToken(from: event.instigator_token)
            self.petitioner_token = AuditToken(from: event.petitioner_token)
        }
        
        self.flags = Int64(event.flags)
        self.right_count = Int32(event.right_count)
        
        var tempRights: [String] = []
        if let rightsPointer = event.rights {
            for i in 0..<event.right_count {
                let right = rightsPointer[i]
                if right.length > 0 {
                    tempRights.append(String(cString: right.data))
                }
            }
        }
        self.rights = tempRights
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension AuthorizationPetitionEvent: ESEnrichable {
    /// Derive the flags' names.
    public mutating func enrich() {
        flags_array = translateFlags(UInt32(truncatingIfNeeded: flags))
    }
}
