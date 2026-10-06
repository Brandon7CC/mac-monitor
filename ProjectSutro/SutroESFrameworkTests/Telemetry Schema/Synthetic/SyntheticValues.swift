//
//  SyntheticValues.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Variants
/// How a synthetic record is filled.
struct SyntheticVariant {
    /// The variant's name, for failures: `full`, `flags`, `new_path`, `empty`.
    let name: String
    /// Fill every optional and give every array an element (`true`), or leave every optional `nil` but those
    /// Endpoint Security never leaves out, and every array empty (`false`).
    let full: Bool
    /// The case each enum with associated values decodes as, by the enum's name.
    var arms: [String: String] = [:]
    /// Integers that choose an encoder's branch, by their key.
    var integers: [String: Int] = [:]
    /// Keys left `nil` on purpose in a full variant, such as the other arm of a union: `Type.key` for one type's, or
    /// `*.key` for every type's. A bare `key` would hide every other type's optional of that name from the gap check.
    var absent: Set<String> = []
    /// Which case a `CaseIterable` value takes: variants spread over the cases.
    var index = 0
    
    /// The message's version: the newest Mac Monitor knows for a full variant, the oldest it runs on (macOS 13.1) for
    /// an empty one.
    var version: Int { full ? 10 : 6 }
}


// MARK: - Values
/// The values a ``SyntheticDecoder`` makes up, by type and key, chosen to survive the event store's conversions and to
/// match eslogger's formats.
enum SyntheticValues {
    /// Every `UUID`.
    static let uuid = UUID(uuidString: "5C4E0000-0000-4000-8000-0000000000A1")!
    /// Every time: eslogger's format, and the same instant as ``date``.
    static let time = "2026-10-05T12:00:00.123456789Z"
    /// Every `Date`.
    static let date = Date(timeIntervalSince1970: 1_791_201_600.123_456)
    /// Every code directory hash.
    static let cdhash = "0123456789ABCDEF0123456789ABCDEF01234567"
    
    /// Optional fields Endpoint Security never leaves out (`_Nonnull` pointers and plain fields), which an empty
    /// variant fills anyway: `Type.key`, or `*.key` for every type.
    static let neverNil: Set<String> = [
        "Process.cdhash", "Process.audit_token", "Process.parent_audit_token", "Process.responsible_audit_token",
        "Process.executable",
        "ActionResultWrapper.result", "ActionResult.result_type", "ActionResult.result", "AuthResult.auth",
        "ProcessExecEvent.cwd", "ProcessExecEvent.last_fd", "ProcessExecEvent.image_cputype",
        "ProcessExecEvent.image_cpusubtype", "FileCloseEvent.was_mapped_writable",
        "*.node_name", "*.user_name", "*.group_name", "*.account_name", "*.record_name", "*.attribute_name",
        "*.attribute_value",
    ]
    
    /// Keys whose value is an object that a decoder probes as a string first (an older export's name in its place):
    /// asked for a string, they have none.
    static let objectKeys: Set<String> = ["member", "thread_state"]
    
    /// A value of a scalar type, by its key.
    ///
    /// - Parameters:
    ///   - type: The type.
    ///   - key: The value's key.
    ///   - variant: How the record is filled.
    /// - Returns: The value, or `nil` for a type that isn't a scalar.
    static func value<T>(of type: T.Type, forKey key: String, in variant: SyntheticVariant) -> Any? {
        switch type {
        case is UUID.Type: return uuid
        case is Date.Type: return date
        case is Data.Type: return Data([0x5C, 0x4E])
        case is Bool.Type: return variant.full
        case is String.Type: return string(forKey: key)
        case is Double.Type: return 1.5
        case is Float.Type: return Float(1.5)
        case let integer as any FixedWidthInteger.Type: return convert(integer, Self.integer(forKey: key, in: variant))
        default: return nil
        }
    }
    
    /// An integer as a fixed-width integer type, its bits kept.
    ///
    /// - Parameters:
    ///   - type: The type.
    ///   - value: The integer.
    /// - Returns: The value.
    private static func convert<N: FixedWidthInteger>(_ type: N.Type, _ value: Int) -> N {
        N(truncatingIfNeeded: value)
    }
    
    /// A string, by its key: a time, a hash, a path or a URL where the key says so.
    ///
    /// - Parameter key: The string's key.
    /// - Returns: The string.
    static func string(forKey key: String) -> String {
        switch key {
        case "time": return time
        case "cdhash": return cdhash
        case "uuid", "member_value": return uuid.uuidString
        case "sha256": return String(repeating: "AB", count: 32)
        case "state_base64": return "AAECAwQFBgc="
        case _ where key.hasSuffix("_url"): return "file:///synthetic/\(key)"
        case _ where key.hasSuffix("path") || key == "dir" || key == "file_path": return "/synthetic/\(key)"
        default: return "synthetic \(key)"
        }
    }
    
    /// An integer, by its key: the variant's, or one that makes sense for the field.
    ///
    /// - Parameters:
    ///   - key: The integer's key.
    ///   - variant: How the record is filled.
    /// - Returns: The integer.
    static func integer(forKey key: String, in variant: SyntheticVariant) -> Int {
        if let chosen = variant.integers[key] { return chosen }
        switch key {
        case "version": return variant.version
        case "schema_version", "action_type": return 1
        case "result_type", "auth", "destination_type", "file_type", "member_type": return 0
        case "tv_sec": return 1_791_201_600
        case "tv_nsec": return 123_456_789
        case "tv_usec": return 123_456
        case "euid", "ruid", "uid", "auid": return variant.full ? 0 : 501
        case "fdtype": return Int(PROX_FDTYPE_PIPE)
        case "flavor": return 6
        case "sig": return 9
        case "cs_validation_category": return Int(ES_CS_VALIDATION_CATEGORY_PLATFORM.rawValue)
        default: return 7
        }
    }
}
