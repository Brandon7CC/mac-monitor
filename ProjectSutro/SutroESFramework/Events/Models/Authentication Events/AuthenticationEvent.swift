//
//  AuthenticationEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/21/26.
//

import Foundation
import EndpointSecurity


// MARK: - Authentication event
/// Models an `ES_EVENT_TYPE_NOTIFY_AUTHENTICATION`: an authentication was performed, by Open Directory (a password),
/// Touch ID, a CryptoTokenKit token (a smart card), or Auto Unlock (an Apple Watch).
///
/// The record is eslogger's: `success`, `type`, and `data` holding the one arm `type` names, as `od`, `touchid`,
/// `token` or `auto_unlock`.
public struct AuthenticationEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    /// Did the authentication succeed?
    public var success: Bool
    /// The kind of authentication, an `es_authentication_type_t`.
    public var type: Int32
    /// What `type` describes: ``AuthenticationData/unknown`` for a type Mac Monitor doesn't know.
    public var data: AuthenticationData
    /// Mac Monitor enrichment: the name of `type`, such as `ES_AUTHENTICATION_TYPE_OD`.
    public var type_string = ""

    /// Record the event of a message from Endpoint Security.
    ///
    /// - Parameter rawMessage: The message.
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event = rawMessage.pointee.event.authentication.pointee
        success = event.success
        type = Int32(truncatingIfNeeded: event.type.rawValue)
        data = .from(event, version: Int(rawMessage.pointee.version))
        enrich()
        /// Any user this Mac knows, read afresh, as a login's is (``LoginLoginEvent``).
        if case .touchid(var touch) = data, let uid = touch.uid,
           let name = Process.userName(Int(uid), systemAccountsOnly: false, remembered: false) {
            touch.uid_human = name
            data = .touchid(touch)
        }
    }

    /// The process that asked for the authentication (the XPC caller), whichever arm holds it. Auto Unlock has none.
    public var instigator: Process? {
        get { data.od?.instigator ?? data.touchid?.instigator ?? data.token?.instigator }
        set {
            switch data {
            case .od(var arm): arm.instigator = newValue; data = .od(arm)
            case .touchid(var arm): arm.instigator = newValue; data = .touchid(arm)
            case .token(var arm): arm.instigator = newValue; data = .token(arm)
            case .auto_unlock, .unknown: break
            }
        }
    }

    /// The instigator's audit token, whichever arm holds it: message version 8 and later.
    public var instigator_token: AuditToken? {
        data.od?.instigator_token ?? data.touchid?.instigator_token ?? data.token?.instigator_token
    }

    /// Who the authentication was for, as the event names them: the Open Directory record, the Auto Unlock user, the
    /// Touch ID user's name or ID, or a token's Kerberos principal. `nil` when the event names no one.
    public var account: String? {
        if let od = data.od { return od.record_name }
        if let unlock = data.auto_unlock { return unlock.username }
        if let touch = data.touchid { return touch.uid_human ?? touch.uid.map(String.init) }
        return data.token?.kerberos_principal
    }
}


// MARK: - The union's arms
/// An authentication's `data`: the arm its `type` names.
public enum AuthenticationData: Hashable, Codable {
    case od(ODAuthentication)
    case touchid(TouchIDAuthentication)
    case token(TokenAuthentication)
    case auto_unlock(AutoUnlockAuthentication)
    /// A `type` this version of Mac Monitor doesn't know: the data can't be read.
    case unknown

    /// Read the arm an event's type names.
    ///
    /// - Parameters:
    ///   - event: The message's event.
    ///   - version: The message's version.
    /// - Returns: The arm, or ``unknown`` for a type that names none.
    static func from(_ event: es_event_authentication_t, version: Int) -> AuthenticationData {
        switch event.type {
        case ES_AUTHENTICATION_TYPE_OD: .od(ODAuthentication(from: event.data.od.pointee, version: version))
        case ES_AUTHENTICATION_TYPE_TOUCHID:
            .touchid(TouchIDAuthentication(from: event.data.touchid.pointee, version: version))
        case ES_AUTHENTICATION_TYPE_TOKEN: .token(TokenAuthentication(from: event.data.token.pointee, version: version))
        case ES_AUTHENTICATION_TYPE_AUTO_UNLOCK:
            .auto_unlock(AutoUnlockAuthentication(from: event.data.auto_unlock.pointee))
        /// A newer macOS's authentication type: recording it beats stopping the Security Extension.
        default: .unknown
        }
    }

    /// Open Directory's arm, or `nil`.
    public var od: ODAuthentication? {
        if case .od(let arm) = self { return arm }
        return nil
    }

    /// Touch ID's arm, or `nil`.
    public var touchid: TouchIDAuthentication? {
        if case .touchid(let arm) = self { return arm }
        return nil
    }

    /// A token's arm, or `nil`.
    public var token: TokenAuthentication? {
        if case .token(let arm) = self { return arm }
        return nil
    }

    /// Auto Unlock's arm, or `nil`.
    public var auto_unlock: AutoUnlockAuthentication? {
        if case .auto_unlock(let arm) = self { return arm }
        return nil
    }
}

/// `es_event_authentication_od_t`: Open Directory checked a record's password.
public struct ODAuthentication: Codable, Hashable {
    /// The process that asked for the authentication (the XPC caller), or `nil` when Endpoint Security leaves it out.
    public var instigator: Process?
    /// The record's type: typically "Users".
    public var record_type: String
    /// The record's name: for "Users", the user name.
    public var record_name: String
    /// The node, such as `/Local/Default`, `/LDAPv3/<server>` or `/Active Directory/<domain>`.
    public var node_name: String
    /// The database of a `/Local/Default` node, or `nil`.
    public var db_path: String?
    /// The instigator's audit token: message version 8 and later.
    public var instigator_token: AuditToken?

    /// - Parameters:
    ///   - event: The arm.
    ///   - version: The message's version.
    init(from event: es_event_authentication_od_t, version: Int) {
        instigator = event.instigator.map { Process(from: $0.pointee, version: version) }
        record_type = event.record_type.string ?? ""
        record_name = event.record_name.string ?? ""
        node_name = event.node_name.string ?? ""
        db_path = event.db_path.string
        instigator_token = version >= 8 ? AuditToken(from: event.instigator_token) : nil
    }
}

/// `es_event_authentication_touchid_t`: Touch ID was asked to verify or identify a user.
public struct TouchIDAuthentication: Codable, Hashable {
    /// The process that asked for the authentication (the XPC caller), or `nil` when Endpoint Security leaves it out.
    public var instigator: Process?
    /// An `es_touchid_mode_t`: verification (0) or identification (1).
    public var touchid_mode: Int32
    /// The user authenticated: `nil` (eslogger's `null`) without one. Set for a verification that succeeded.
    public var uid: Int64?
    /// The instigator's audit token: message version 8 and later.
    public var instigator_token: AuditToken?
    /// Mac Monitor enrichment: the name of `touchid_mode`, and the user's name, `nil` without a user ID.
    public var touchid_mode_string = ""
    public var uid_human: String?

    /// - Parameters:
    ///   - event: The arm.
    ///   - version: The message's version.
    init(from event: es_event_authentication_touchid_t, version: Int) {
        instigator = event.instigator.map { Process(from: $0.pointee, version: version) }
        touchid_mode = Int32(truncatingIfNeeded: event.touchid_mode.rawValue)
        uid = event.has_uid ? Int64(event.uid.uid) : nil
        instigator_token = version >= 8 ? AuditToken(from: event.instigator_token) : nil
    }
}

/// `es_event_authentication_token_t`: CryptoTokenKit authenticated with a token, such as a smart card.
public struct TokenAuthentication: Codable, Hashable {
    /// The process that asked for the authentication (the XPC caller), or `nil` when Endpoint Security leaves it out.
    public var instigator: Process?
    /// The hash of the public key CryptoTokenKit authenticated with.
    public var pubkey_hash: String
    /// The token's identifier.
    public var token_id: String
    /// The Kerberos principal, when the token got a ticket-granting ticket (GSS PKINIT). `nil` otherwise.
    public var kerberos_principal: String?
    /// The instigator's audit token: message version 8 and later.
    public var instigator_token: AuditToken?

    /// - Parameters:
    ///   - event: The arm.
    ///   - version: The message's version.
    init(from event: es_event_authentication_token_t, version: Int) {
        instigator = event.instigator.map { Process(from: $0.pointee, version: version) }
        pubkey_hash = event.pubkey_hash.string ?? ""
        token_id = event.token_id.string ?? ""
        kerberos_principal = event.kerberos_principal.string
        instigator_token = version >= 8 ? AuditToken(from: event.instigator_token) : nil
    }
}

/// `es_event_authentication_auto_unlock_t`: an Apple Watch unlocked the Mac or approved an authorization prompt.
public struct AutoUnlockAuthentication: Codable, Hashable {
    /// The user the authentication was attempted for.
    public var username: String
    /// An `es_auto_unlock_type_t`: unlocking the Mac (1) or approving an authorization prompt (2).
    public var type: Int32
    /// Mac Monitor enrichment: the name of `type`.
    public var type_string = ""

    /// - Parameter event: The arm.
    init(from event: es_event_authentication_auto_unlock_t) {
        username = event.username.string ?? ""
        type = Int32(truncatingIfNeeded: event.type.rawValue)
    }
}


// MARK: - Mac Monitor enrichment
extension AuthenticationEvent: ESEnrichable {
    /// `es_authentication_type_t`: the kind of authentication.
    static let typeNames = ConstantNames([
        ES_AUTHENTICATION_TYPE_OD.rawValue: "ES_AUTHENTICATION_TYPE_OD",
        ES_AUTHENTICATION_TYPE_TOUCHID.rawValue: "ES_AUTHENTICATION_TYPE_TOUCHID",
        ES_AUTHENTICATION_TYPE_TOKEN.rawValue: "ES_AUTHENTICATION_TYPE_TOKEN",
        ES_AUTHENTICATION_TYPE_AUTO_UNLOCK.rawValue: "ES_AUTHENTICATION_TYPE_AUTO_UNLOCK",
    ])

    /// `es_touchid_mode_t`: what Touch ID was asked to do.
    static let touchIDModeNames = ConstantNames([
        ES_TOUCHID_MODE_VERIFICATION.rawValue: "ES_TOUCHID_MODE_VERIFICATION",
        ES_TOUCHID_MODE_IDENTIFICATION.rawValue: "ES_TOUCHID_MODE_IDENTIFICATION",
    ])

    /// `es_auto_unlock_type_t`: what Auto Unlock was for.
    static let autoUnlockTypeNames = ConstantNames([
        ES_AUTO_UNLOCK_MACHINE_UNLOCK.rawValue: "ES_AUTO_UNLOCK_MACHINE_UNLOCK",
        ES_AUTO_UNLOCK_AUTH_PROMPT.rawValue: "ES_AUTO_UNLOCK_AUTH_PROMPT",
    ])

    /// Derive the names of the type, the Touch ID mode and the Auto Unlock type, and the Touch ID user's name if
    /// it's a system account.
    ///
    /// Not derived: the names of other users (read from this Mac as the event is captured).
    public mutating func enrich() {
        type_string = Self.typeNames.name(of: Int(type))
        switch data {
        case .touchid(var touch):
            touch.touchid_mode_string = Self.touchIDModeNames.name(of: Int(touch.touchid_mode))
            touch.uid_human = touch.uid.flatMap { Process.userName(Int($0), systemAccountsOnly: true) }
                ?? touch.uid_human
            data = .touchid(touch)
        case .auto_unlock(var unlock):
            unlock.type_string = Self.autoUnlockTypeNames.name(of: Int(unlock.type))
            data = .auto_unlock(unlock)
        case .od, .token, .unknown:
            break
        }
    }
}
