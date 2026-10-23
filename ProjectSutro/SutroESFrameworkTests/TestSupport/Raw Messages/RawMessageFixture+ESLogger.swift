//
//  RawMessageFixture+ESLogger.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - JSON values
/// Reads the values of an eslogger record's objects.
private extension Dictionary where Key == String, Value == Any {
    /// A number, or 0 when it's missing.
    ///
    /// - Parameter key: The number's key.
    /// - Returns: The number.
    func number(_ key: String) -> NSNumber {
        self[key] as? NSNumber ?? 0
    }
    
    /// An object, or an empty one when it's missing.
    ///
    /// - Parameter key: The object's key.
    /// - Returns: The object.
    func object(_ key: String) -> [String: Any] {
        self[key] as? [String: Any] ?? [:]
    }
    
    /// A UTC time, as eslogger writes one.
    ///
    /// - Parameter key: The time's key.
    /// - Returns: The time, or 1970 when it's missing.
    func time(_ key: String) -> timespec {
        (self[key] as? String).flatMap(ESLogger.utcTimespec(from:)) ?? timespec()
    }
}


// MARK: - Structs from eslogger's JSON
/// Builds Endpoint Security's structs from the values eslogger wrote for them, so that a test can record an event
/// eslogger recorded and compare Mac Monitor's export with eslogger's record.
extension RawMessageFixture {
    /// An audit token from eslogger's object for it.
    ///
    /// - Parameter object: The token's object.
    /// - Returns: The token.
    static func auditToken(eslogger object: [String: Any]) -> audit_token_t {
        let field = { (key: String) in UInt32(truncatingIfNeeded: object.number(key).int64Value) }
        return audit_token_t(val: (field("auid"), field("euid"), field("egid"), field("ruid"), field("rgid"),
                                   field("pid"), field("asid"), field("pidversion")))
    }
    
    /// A file from eslogger's object for it.
    ///
    /// - Parameter object: The file's object.
    /// - Returns: The file.
    func file(eslogger object: [String: Any]) -> UnsafeMutablePointer<es_file_t> {
        let file = allocate(es_file_t.self)
        file.pointee.path = token(object["path"] as? String)
        file.pointee.path_truncated = object.number("path_truncated").boolValue
        let stat = object.object("stat")
        file.pointee.stat.st_dev = dev_t(truncatingIfNeeded: stat.number("st_dev").int64Value)
        file.pointee.stat.st_mode = mode_t(truncatingIfNeeded: stat.number("st_mode").int64Value)
        file.pointee.stat.st_nlink = nlink_t(truncatingIfNeeded: stat.number("st_nlink").int64Value)
        file.pointee.stat.st_ino = stat.number("st_ino").uint64Value
        file.pointee.stat.st_uid = uid_t(truncatingIfNeeded: stat.number("st_uid").int64Value)
        file.pointee.stat.st_gid = gid_t(truncatingIfNeeded: stat.number("st_gid").int64Value)
        file.pointee.stat.st_rdev = dev_t(truncatingIfNeeded: stat.number("st_rdev").int64Value)
        file.pointee.stat.st_atimespec = stat.time("st_atimespec")
        file.pointee.stat.st_mtimespec = stat.time("st_mtimespec")
        file.pointee.stat.st_ctimespec = stat.time("st_ctimespec")
        file.pointee.stat.st_birthtimespec = stat.time("st_birthtimespec")
        file.pointee.stat.st_size = stat.number("st_size").int64Value
        file.pointee.stat.st_blocks = stat.number("st_blocks").int64Value
        file.pointee.stat.st_blksize = blksize_t(truncatingIfNeeded: stat.number("st_blksize").int64Value)
        file.pointee.stat.st_flags = UInt32(truncatingIfNeeded: stat.number("st_flags").int64Value)
        file.pointee.stat.st_gen = UInt32(truncatingIfNeeded: stat.number("st_gen").int64Value)
        return file
    }
    
    /// A process from eslogger's object for it.
    ///
    /// - Parameter object: The process's object. Its `cdhash` is 40 hex digits.
    /// - Returns: The process.
    func process(eslogger object: [String: Any]) -> UnsafeMutablePointer<es_process_t> {
        let process = allocate(es_process_t.self)
        process.pointee.audit_token = Self.auditToken(eslogger: object.object("audit_token"))
        process.pointee.ppid = pid_t(truncatingIfNeeded: object.number("ppid").int64Value)
        process.pointee.original_ppid = pid_t(truncatingIfNeeded: object.number("original_ppid").int64Value)
        process.pointee.group_id = pid_t(truncatingIfNeeded: object.number("group_id").int64Value)
        process.pointee.session_id = pid_t(truncatingIfNeeded: object.number("session_id").int64Value)
        process.pointee.codesigning_flags = UInt32(truncatingIfNeeded: object.number("codesigning_flags").int64Value)
        process.pointee.is_platform_binary = object.number("is_platform_binary").boolValue
        process.pointee.is_es_client = object.number("is_es_client").boolValue
        let hex = Array((object["cdhash"] as? String ?? "").utf8)
        withUnsafeMutableBytes(of: &process.pointee.cdhash) { cdhash in
            for index in cdhash.indices where index * 2 + 1 < hex.count {
                cdhash[index] = UInt8(String(decoding: hex[index * 2...index * 2 + 1], as: UTF8.self), radix: 16) ?? 0
            }
        }
        process.pointee.signing_id = token(object["signing_id"] as? String)
        process.pointee.team_id = token(object["team_id"] as? String)
        process.pointee.executable = file(eslogger: object.object("executable"))
        process.pointee.tty = (object["tty"] as? [String: Any]).map { file(eslogger: $0) }
        let start = object.time("start_time")
        process.pointee.start_time = timeval(tv_sec: start.tv_sec, tv_usec: Int32(start.tv_nsec / 1_000))
        process.pointee.responsible_audit_token = Self.auditToken(eslogger: object.object("responsible_audit_token"))
        process.pointee.parent_audit_token = Self.auditToken(eslogger: object.object("parent_audit_token"))
        process.pointee.cs_validation_category = es_cs_validation_category_t(
            rawValue: object.number("cs_validation_category").uint32Value)
        return process
    }
    
    /// Fill in the message's envelope from an eslogger record: its version, event type, times, sequence numbers,
    /// thread and process. The event stays all zeros.
    ///
    /// - Parameter record: The record.
    func fillEnvelope(eslogger record: [String: Any]) {
        message.pointee.version = record.number("version").uint32Value
        message.pointee.event_type = es_event_type_t(rawValue: record.number("event_type").uint32Value)
        message.pointee.action_type = es_action_type_t(rawValue: record.number("action_type").uint32Value)
        message.pointee.time = record.time("time")
        message.pointee.mach_time = record.number("mach_time").uint64Value
        message.pointee.seq_num = record.number("seq_num").uint64Value
        message.pointee.global_seq_num = record.number("global_seq_num").uint64Value
        /// `NULL` for eslogger's `"thread": null`, as Endpoint Security leaves it.
        message.pointee.thread = (record["thread"] as? [String: Any]).map {
            pointer(es_thread_t(thread_id: $0.number("thread_id").uint64Value))
        }
        message.pointee.process = process(eslogger: record.object("process"))
    }
}

extension XCTestCase {
    /// A record captured as the Security Extension captures it: its envelope and event in Endpoint Security's structs.
    ///
    /// - Parameters:
    ///   - record: eslogger's record.
    ///   - version: The message's version, if not the record's.
    ///   - fill: Places the record's event in the message, such as ``RawMessageFixture/fillODEvent(eslogger:)``;
    ///     `false` if it can't.
    /// - Returns: The event.
    func capture(eslogger record: [String: Any], version: UInt32? = nil,
                 fill: (RawMessageFixture) -> Bool) -> Message {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
        fixture.fillEnvelope(eslogger: record)
        XCTAssertTrue(fill(fixture))
        if let version { fixture.message.pointee.version = version }
        return Message(from: fixture.raw)
    }
}


// MARK: - Open Directory events
/// An `es_event_od_*_t` whose common fields a test can set.
protocol SettableODEvent: ODEventFields {
    var instigator: UnsafeMutablePointer<es_process_t>? { get set }
    var error_code: Int32 { get set }
    var node_name: es_string_token_t { get set }
    var db_path: es_string_token_t { get set }
    var instigator_token: audit_token_t { get set }
    
    /// Point the event's other `_Nonnull` pointers at zeroed values.
    ///
    /// - Parameter fixture: The message the event belongs to, which owns the values.
    mutating func fillRequiredPointers(from fixture: RawMessageFixture)
}

extension SettableODEvent {
    /// Most Open Directory events have no other pointers.
    ///
    /// - Parameter fixture: The message the event belongs to.
    mutating func fillRequiredPointers(from fixture: RawMessageFixture) {}
}

/// An `es_event_od_group_add_t` or `es_event_od_group_remove_t`, whose member a test can set.
protocol SettableODGroupMemberEvent: SettableODEvent {
    var group_name: es_string_token_t { get set }
    var member: UnsafeMutablePointer<es_od_member_id_t> { get set }
}

extension SettableODGroupMemberEvent {
    /// The group's member.
    ///
    /// - Parameter fixture: The message the event belongs to, which owns the member.
    mutating func fillRequiredPointers(from fixture: RawMessageFixture) {
        member = fixture.allocate(es_od_member_id_t.self)
    }
}

extension es_event_od_create_user_t: SettableODEvent {}
extension es_event_od_create_group_t: SettableODEvent {}
extension es_event_od_modify_password_t: SettableODEvent {}
extension es_event_od_attribute_value_add_t: SettableODEvent {}
extension es_event_od_group_add_t: SettableODGroupMemberEvent {}
extension es_event_od_group_remove_t: SettableODGroupMemberEvent {}

extension RawMessageFixture {
    /// Places an Open Directory event in a message, with the common fields of eslogger's object for it.
    typealias ODPlacement = (RawMessageFixture, [String: Any]) -> Void
    
    /// Every Open Directory event Mac Monitor records: its key, its type, and how to place it in a message.
    static let openDirectoryEvents: [(name: String, type: es_event_type_t, place: ODPlacement)] = [
        ("od_create_user", ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER, { $0.odEvent(\.od_create_user, eslogger: $1) }),
        ("od_create_group", ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP, { $0.odEvent(\.od_create_group, eslogger: $1) }),
        ("od_group_add", ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD, { $0.odEvent(\.od_group_add, eslogger: $1) }),
        ("od_group_remove", ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE, { $0.odEvent(\.od_group_remove, eslogger: $1) }),
        ("od_modify_password", ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD,
         { $0.odEvent(\.od_modify_password, eslogger: $1) }),
        ("od_attribute_value_add", ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD,
         { $0.odEvent(\.od_attribute_value_add, eslogger: $1) }),
    ]
    
    /// Place a new Open Directory event in the message, with the common fields of eslogger's object for it.
    ///
    /// - Parameters:
    ///   - slot: The event's place in the message's `event` union.
    ///   - object: eslogger's object for the event: no `instigator` (or `null`) leaves it `NULL`, and no
    ///     `instigator_token` leaves it zeroed.
    /// - Returns: The event, for the test to fill in its own fields.
    @discardableResult
    func odEvent<Event: SettableODEvent>(_ slot: WritableKeyPath<es_events_t, UnsafeMutablePointer<Event>>,
                                         eslogger object: [String: Any] = [:]) -> UnsafeMutablePointer<Event> {
        let event = allocate(Event.self)
        event.pointee.fillRequiredPointers(from: self)
        event.pointee.instigator = (object["instigator"] as? [String: Any]).map { process(eslogger: $0) }
        event.pointee.error_code = Int32(truncatingIfNeeded: object.number("error_code").int64Value)
        event.pointee.node_name = token(object["node_name"] as? String)
        event.pointee.db_path = token(object["db_path"] as? String)
        if let instigatorToken = object["instigator_token"] as? [String: Any] {
            event.pointee.instigator_token = Self.auditToken(eslogger: instigatorToken)
        }
        message.pointee.event[keyPath: slot] = event
        return event
    }
    
    /// Set a group event's member.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - type: The member's `es_od_member_type_t`.
    ///   - value: The user's name for type 0, or the UUID for types 1 and 2. `nil` leaves the name `NULL`.
    func setMember(of event: UnsafeMutablePointer<some SettableODGroupMemberEvent>, type: Int, value: String?) {
        let member = event.pointee.member
        member.pointee.member_type = es_od_member_type_t(rawValue: UInt32(truncatingIfNeeded: type))
        if type == 1 || type == 2, let uuid = value.flatMap(UUID.init(uuidString:)) {
            member.pointee.member_value.uuid = uuid.uuid
        } else {
            member.pointee.member_value.name = token(value)
        }
    }
    
    /// Set a group event's own fields from eslogger's object for it.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - object: eslogger's object for the event.
    private func fillGroupMember(_ event: UnsafeMutablePointer<some SettableODGroupMemberEvent>,
                                 eslogger object: [String: Any]) {
        event.pointee.group_name = token(object["group_name"] as? String)
        let member = object.object("member")
        setMember(of: event, type: member.number("member_type").intValue, value: member["member_value"] as? String)
    }
    
    /// Place the Open Directory event of an eslogger record in the message, with all its fields.
    ///
    /// - Parameter record: The record. Its event is one of the six Mac Monitor records.
    /// - Returns: `false` if the record holds another event.
    func fillODEvent(eslogger record: [String: Any]) -> Bool {
        guard let (name, value) = record.object("event").first, let object = value as? [String: Any] else {
            return false
        }
        let text = { (key: String) in self.token(object[key] as? String) }
        switch name {
        case "od_create_user":
            odEvent(\.od_create_user, eslogger: object).pointee.user_name = text("user_name")
        case "od_create_group":
            odEvent(\.od_create_group, eslogger: object).pointee.group_name = text("group_name")
        case "od_group_add":
            fillGroupMember(odEvent(\.od_group_add, eslogger: object), eslogger: object)
        case "od_group_remove":
            fillGroupMember(odEvent(\.od_group_remove, eslogger: object), eslogger: object)
        case "od_modify_password":
            let event = odEvent(\.od_modify_password, eslogger: object)
            event.pointee.account_type = es_od_account_type_t(rawValue: object.number("account_type").uint32Value)
            event.pointee.account_name = text("account_name")
        case "od_attribute_value_add":
            let event = odEvent(\.od_attribute_value_add, eslogger: object)
            event.pointee.record_type = es_od_record_type_t(rawValue: object.number("record_type").uint32Value)
            event.pointee.record_name = text("record_name")
            event.pointee.attribute_name = text("attribute_name")
            event.pointee.attribute_value = text("attribute_value")
        default:
            return false
        }
        return true
    }
}
