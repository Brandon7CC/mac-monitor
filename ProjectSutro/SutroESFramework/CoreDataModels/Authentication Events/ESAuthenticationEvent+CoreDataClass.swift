//
//  ESAuthenticationEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/21/26.
//

import Foundation
import CoreData
import EndpointSecurity


/// A stored `authentication` event (``AuthenticationEvent``). The arms of its `data` are kept flat, each in the
/// columns only it has, with the one instigator and its audit token, and written back as eslogger nests them.
@objc(ESAuthenticationEvent)
public class ESAuthenticationEvent: NSManagedObject, Identifiable {
    @NSManaged public var success: Bool
    @NSManaged public var type: Int32
    /// The process that asked for the authentication, whichever arm held it. Auto Unlock has none.
    @NSManaged public var instigator: ESProcess?
    @NSManaged public var instigator_token: ESAuditToken?
    /// Open Directory's arm.
    @NSManaged public var record_type: String?
    @NSManaged public var record_name: String?
    @NSManaged public var node_name: String?
    @NSManaged public var db_path: String?
    /// Touch ID's arm.
    @NSManaged public var touchid_mode: NSNumber?
    @NSManaged public var uid: NSNumber?
    /// A token's arm.
    @NSManaged public var pubkey_hash: String?
    @NSManaged public var token_id: String?
    @NSManaged public var kerberos_principal: String?
    /// Auto Unlock's arm.
    @NSManaged public var username: String?
    @NSManaged public var auto_unlock_type: NSNumber?

    /// Mac Monitor enrichment
    @NSManaged public var type_string: String?
    @NSManaged public var touchid_mode_string: String?
    @NSManaged public var uid_human: String?
    @NSManaged public var auto_unlock_type_string: String?

    /// The event's keys, and the arms `data` holds.
    enum CodingKeys: CodingKey {
        case success, type, data, type_string
    }

    enum ArmKeys: CodingKey {
        case od, touchid, token, auto_unlock
    }

    /// Every arm's keys: eslogger's, then Mac Monitor's.
    enum FieldKeys: CodingKey {
        case instigator, record_type, record_name, node_name, db_path, instigator_token
        case touchid_mode, uid, touchid_mode_string, uid_human
        case pubkey_hash, token_id, kerberos_principal
        case username, type, type_string
    }

    /// Store an event.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - message: The event's message.
    ///   - context: The context to insert into.
    convenience init(from event: AuthenticationEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        success = event.success
        type = event.type
        type_string = event.type_string
        /// The process and its token each on their own: Endpoint Security can leave out the process (`NULL`) and
        /// still give its token, and before message version 8 gives the process without one.
        instigator = ESProcess.insert(event.instigator, version: message.version, in: context)
        instigator_token = ESAuditToken.insert(event.instigator_token, in: context)
        if let od = event.data.od {
            (record_type, record_name, node_name, db_path) = (od.record_type, od.record_name, od.node_name, od.db_path)
        }
        if let touch = event.data.touchid {
            touchid_mode = NSNumber(value: touch.touchid_mode)
            touchid_mode_string = touch.touchid_mode_string
            uid = touch.uid.map { NSNumber(value: $0) }
            uid_human = touch.uid_human
        }
        if let token = event.data.token {
            (pubkey_hash, token_id, kerberos_principal) = (token.pubkey_hash, token.token_id, token.kerberos_principal)
        }
        if let unlock = event.data.auto_unlock {
            username = unlock.username
            auto_unlock_type = NSNumber(value: unlock.type)
            auto_unlock_type_string = unlock.type_string
        }
    }

    /// Who the authentication was for (``AuthenticationEvent/account``).
    public var account: String? {
        switch es_authentication_type_t(UInt32(truncatingIfNeeded: type)) {
        case ES_AUTHENTICATION_TYPE_OD: record_name
        case ES_AUTHENTICATION_TYPE_AUTO_UNLOCK: username
        case ES_AUTHENTICATION_TYPE_TOUCHID: uid_human ?? uid?.stringValue
        case ES_AUTHENTICATION_TYPE_TOKEN: kerberos_principal
        default: nil
        }
    }
}


// MARK: - Encodable conformance
extension ESAuthenticationEvent: Encodable {
    /// Encode the event as eslogger nests it: `data` holds the arm `type` names, and nothing for a type Mac Monitor
    /// doesn't know. A value Endpoint Security left out is `null`, as eslogger writes it.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: The error encoding a field.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(success, forKey: .success)
        try container.encode(type, forKey: .type)
        try container.encode(type_string, forKey: .type_string)
        var data = container.nestedContainer(keyedBy: ArmKeys.self, forKey: .data)
        switch es_authentication_type_t(UInt32(truncatingIfNeeded: type)) {
        case ES_AUTHENTICATION_TYPE_OD:
            var arm = data.nestedContainer(keyedBy: FieldKeys.self, forKey: .od)
            try arm.encode(instigator, forKey: .instigator)
            try arm.encode(record_type, forKey: .record_type)
            try arm.encode(record_name, forKey: .record_name)
            try arm.encode(node_name, forKey: .node_name)
            try arm.encode(db_path, forKey: .db_path)
            try arm.encode(instigator_token, forKey: .instigator_token)
        case ES_AUTHENTICATION_TYPE_TOUCHID:
            var arm = data.nestedContainer(keyedBy: FieldKeys.self, forKey: .touchid)
            try arm.encode(instigator, forKey: .instigator)
            try arm.encode(touchid_mode?.int32Value, forKey: .touchid_mode)
            try arm.encode(touchid_mode_string, forKey: .touchid_mode_string)
            try arm.encode(uid?.int64Value, forKey: .uid)
            try arm.encode(uid_human, forKey: .uid_human)
            try arm.encode(instigator_token, forKey: .instigator_token)
        case ES_AUTHENTICATION_TYPE_TOKEN:
            var arm = data.nestedContainer(keyedBy: FieldKeys.self, forKey: .token)
            try arm.encode(instigator, forKey: .instigator)
            try arm.encode(pubkey_hash, forKey: .pubkey_hash)
            try arm.encode(token_id, forKey: .token_id)
            try arm.encode(kerberos_principal, forKey: .kerberos_principal)
            try arm.encode(instigator_token, forKey: .instigator_token)
        case ES_AUTHENTICATION_TYPE_AUTO_UNLOCK:
            var arm = data.nestedContainer(keyedBy: FieldKeys.self, forKey: .auto_unlock)
            try arm.encode(username, forKey: .username)
            try arm.encode(auto_unlock_type?.int32Value, forKey: .type)
            try arm.encode(auto_unlock_type_string, forKey: .type_string)
        default:
            break
        }
    }
}
