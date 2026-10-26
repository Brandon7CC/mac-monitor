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


public struct AuthorizationPetitionEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var instigator, petitioner: Process?
    public var flags: Int64
    public var flags_array: [String] = []
    public var right_count: Int32
    public var rights: [String]
    
    // Available in msg versions >= 8.
    public var instigator_token, petitioner_token: AuditToken?
    
    /// The names of the petition's flags (`AuthorizationFlags` in `Authorization/Authorization.h`), in bit order.
    private static let flagNames: [(flag: UInt32, name: String)] = [
        (1 << 0, "kAuthorizationFlagInteractionAllowed"),
        (1 << 1, "kAuthorizationFlagExtendRights"),
        (1 << 2, "kAuthorizationFlagPartialRights"),
        (1 << 3, "kAuthorizationFlagDestroyRights"),
        (1 << 4, "kAuthorizationFlagPreAuthorize"),
        (1 << 20, "kAuthorizationFlagNoData"),
    ]
    
    /// The names of the flags that are set.
    ///
    /// - Parameter rawFlags: The petition's flags.
    /// - Returns: Each set flag's name, in bit order. None for `kAuthorizationFlagDefaults` (0).
    static func flagNames(_ rawFlags: UInt32) -> [String] {
        flagNames.filter { rawFlags & $0.flag != 0 }.map(\.name)
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_authorization_petition_t = rawMessage.pointee.event.authorization_petition.pointee
        let version: Int = Int(rawMessage.pointee.version)
        
        self.instigator = event.instigator.map { Process(from: $0.pointee, version: version) }
        self.petitioner = event.petitioner.map { Process(from: $0.pointee, version: version) }
        
        if version >= 8 {
            self.instigator_token = AuditToken(from: event.instigator_token)
            self.petitioner_token = AuditToken(from: event.petitioner_token)
        }
        
        self.flags = Int64(event.flags)
        self.right_count = Int32(event.right_count)
        
        /// Every right, empty ones included, as eslogger writes them.
        self.rights = event.rights.map { rights in (0..<event.right_count).map { rights[$0].string ?? "" } } ?? []
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension AuthorizationPetitionEvent: ESEnrichable {
    /// Derive the flags' names.
    public mutating func enrich() {
        flags_array = Self.flagNames(UInt32(truncatingIfNeeded: flags))
    }
}
