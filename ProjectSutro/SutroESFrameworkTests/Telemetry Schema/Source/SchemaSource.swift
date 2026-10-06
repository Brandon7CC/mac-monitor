//
//  SchemaSource.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Describing the export
/// eslogger's value formats, as patterns every JSON Schema validator reads alike: `[0-9]`, never `\d`.
enum SchemaPattern: String, CaseIterable {
    /// A `timespec` in UTC with nanoseconds: `2026-10-05T12:00:00.123456789Z`.
    case timespec = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{9}Z$"
    /// A `timeval` in UTC with microseconds: `2026-10-05T12:00:00.123456Z`.
    case timeval = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{6}Z$"
    /// A code directory hash: 20 bytes in uppercase hex.
    case cdhash = "^[0-9A-F]{40}$"
    /// A UUID in uppercase, as Foundation writes one.
    case uuid = "^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
    /// A file's SHA-256 in uppercase hex, or Mac Monitor's `NULL` when there's none, where eslogger writes `null`.
    case sha256 = "^([0-9A-F]{64}|NULL)$"
}

/// A key's value, as the schema describes it.
indirect enum SchemaValue {
    /// Any string, integer or Boolean.
    case string, integer, boolean
    /// Always `null`.
    case null
    /// A string in one of eslogger's formats.
    case pattern(SchemaPattern)
    /// One string.
    case constant(String)
    /// One of these strings: only from a `CaseIterable` source or the SDK's event list, so it can't drift.
    case values([String])
    /// One of these integers: the SDK's event numbers.
    case integers([Int])
    /// An array of values.
    case array(SchemaValue)
    /// An object described in place.
    case object(SchemaObject)
    /// A shared definition, by its name in `$defs`.
    case ref(String)
    /// The value, or `null`.
    case nullable(SchemaValue)
    /// One of these values.
    case either([SchemaValue])
}

/// When a key is left out of a record.
struct Absence {
    /// Why: completes "Absent when …".
    let reason: String
    /// Can the tests' synthetic records leave the key out? `false` for absences a macOS 27 test machine can't produce,
    /// such as a key an older macOS's exporter omits.
    var observable = true
    
    /// - Parameters:
    ///   - reason: Why the key is left out: completes "Absent when …".
    ///   - observable: Can the tests' synthetic records leave the key out?
    init(_ reason: String, observable: Bool = true) {
        self.reason = reason
        self.observable = observable
    }
}

/// One key of an object.
struct SchemaKey {
    /// The key.
    let name: String
    /// Who defines it.
    let origin: KeyOrigin
    /// Its value.
    let value: SchemaValue
    /// What it holds, and for Mac Monitor's keys how it's derived.
    let description: String?
    /// When it's left out, for a key that isn't always written.
    let absence: Absence?
    
    /// The description the schema writes: the key's own, then when it's absent.
    var fullDescription: String? {
        let parts = [description, absence.map { "Absent when \($0.reason)." }].compactMap { $0 }
        return parts.isEmpty ? nil : parts.joined(separator: " ")
    }
}

/// An object: its keys, in the order the export writes them.
struct SchemaObject {
    /// What the object is.
    let description: String?
    /// Its keys.
    let keys: [SchemaKey]
    /// How many keys it may have, for an object that holds one of its keys: the event dispatcher.
    var keyCount: ClosedRange<Int>?
    
    /// - Parameters:
    ///   - description: What the object is.
    ///   - keys: Its keys.
    ///   - keyCount: How many keys it may have.
    init(_ description: String?, _ keys: [SchemaKey], keyCount: ClosedRange<Int>? = nil) {
        self.description = description
        self.keys = keys
        self.keyCount = keyCount
    }
}

/// An event type Mac Monitor records, and its event's object.
struct SchemaEvent {
    /// The event's type.
    let type: es_event_type_t
    /// The event's object.
    let object: SchemaObject
    
    /// The event's key under `event`, as eslogger names it: `exec`, `od_create_user`.
    var name: String { constant.dropFirst(SchemaEvent.prefix.count).lowercased() }
    /// The type's SDK name, which Mac Monitor writes as `es_event_type`: `ES_EVENT_TYPE_NOTIFY_EXEC`.
    var constant: String { eventTypeToString(from: type) }
    /// The type's number, which eslogger writes as `event_type`.
    var number: Int { Int(type.rawValue) }
    /// The name of the event's object in `$defs`: `exec_event`.
    var definition: String { "\(name)_event" }
    /// What every notify event's SDK name starts with.
    static let prefix = "ES_EVENT_TYPE_NOTIFY_"
    
    /// - Parameters:
    ///   - type: The event's type.
    ///   - object: The event's object.
    init(_ type: es_event_type_t, _ object: SchemaObject) {
        self.type = type
        self.object = object
    }
}


// MARK: - Keys
/// One of eslogger's keys: at eslogger's path, with eslogger's value.
///
/// - Parameters:
///   - name: The key.
///   - value: Its value.
///   - description: What it holds, where that adds something.
///   - absent: When it's left out, for a key that isn't always written.
/// - Returns: The key.
func eslogger(_ name: String, _ value: SchemaValue, _ description: String? = nil, absent: Absence? = nil) -> SchemaKey {
    SchemaKey(name: name, origin: .eslogger, value: value, description: description, absence: absent)
}

/// One of Mac Monitor's additions beside eslogger's keys, which must say what it holds and how it's derived.
///
/// - Parameters:
///   - name: The key.
///   - value: Its value.
///   - description: What it holds and how it's derived.
///   - absent: When it's left out, for a key that isn't always written.
/// - Returns: The key.
func addition(_ name: String, _ value: SchemaValue, _ description: String, absent: Absence? = nil) -> SchemaKey {
    SchemaKey(name: name, origin: .macMonitor, value: value, description: description, absence: absent)
}

/// An event of a type, as a ``SchemaEvent``.
///
/// - Parameters:
///   - type: The event's type.
///   - description: What the event is.
///   - keys: The event's keys.
/// - Returns: The event.
func event(_ type: es_event_type_t, _ description: String, _ keys: [SchemaKey]) -> SchemaEvent {
    SchemaEvent(type, SchemaObject(description, keys))
}

/// eslogger's integer and Mac Monitor's name for it: `type` and `type_string`.
///
/// - Parameters:
///   - name: eslogger's key.
///   - suffix: What Mac Monitor's key adds to it.
///   - description: What the integer is: the name's description says it's named from it.
/// - Returns: The two keys.
func named(_ name: String, suffix: String = "_string", _ description: String) -> [SchemaKey] {
    [eslogger(name, .integer, description),
     addition(name + suffix, .string, "The name of `\(name)`, from the SDK's constants.")]
}
