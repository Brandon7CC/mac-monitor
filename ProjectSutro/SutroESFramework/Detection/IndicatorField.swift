//
//  IndicatorField.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Indicator fields
/// A record's key path that the Security Extension reads from an event as it captures it, to evaluate an indicator
/// there rather than on the record. Each one's value is the record's, in every case (`MessageValuesParityTests`,
/// `RecordFieldParityTests`).
///
/// Two kinds:
/// - **Direct** (``allCases``): the event's type, the 28 key paths Mac Monitor's shipped indicators compare, and the
///   rest of the signing identity: the exec target's team ID and platform binary, and the process's team ID. Each
///   is read with one `switch` to its leaf (``MessageValues``), the cheapest read there is.
/// - **Record**: any other key path of the telemetry schema whose value is a string, a number, a Boolean or an array of
///   strings, read from the event's own encoding (``RecordPathTrie``). Its number is given the first time a rule
///   names it (``RecordFields``), so a field a later build adds to an event can be compared with no change here.
///
/// The raw values of direct fields are their places in ``allCases``, from 0, and record fields' follow them, so a lane
/// can keep a value per field in an array (``MessageValueCache``).
public struct IndicatorField: Hashable, Sendable {
    /// The field's number: its place among the direct fields, or after them for a record field.
    public let rawValue: UInt16

    /// - Parameter rawValue: The field's number.
    init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    /// What a field's value is, as a predicate on the record compares it.
    public enum Kind: Sendable {
        /// A string, or `nil`.
        case string
        /// A number, or `nil`.
        case number
        /// `true` or `false`, which compares as the number 1 or 0, as `NSNumber` does.
        case boolean
        /// An array of strings, which `ANY` compares.
        case strings
    }

    // MARK: Message
    public static let esEventType = Self(rawValue: 0), context = Self(rawValue: 1), targetPath = Self(rawValue: 2)
    // MARK: Initiating process
    public static let processExecutablePath = Self(rawValue: 3), processExecutableName = Self(rawValue: 4)
    public static let processSigningID = Self(rawValue: 5), processTeamID = Self(rawValue: 6)
    public static let processIsPlatformBinary = Self(rawValue: 7), processCodesigningType = Self(rawValue: 8)
    public static let processIsAdhocSigned = Self(rawValue: 9)
    // MARK: Exec
    public static let execCommandLine = Self(rawValue: 10), execEnv = Self(rawValue: 11)
    public static let execScriptContent = Self(rawValue: 12), execExecutableAge = Self(rawValue: 13)
    public static let execTargetSigningID = Self(rawValue: 14), execTargetTeamID = Self(rawValue: 15)
    public static let execTargetIsPlatformBinary = Self(rawValue: 16), execTargetIsAdhocSigned = Self(rawValue: 17)
    public static let execTargetCodesigningType = Self(rawValue: 18), execTargetExecutablePath = Self(rawValue: 19)
    public static let execTargetExecutableName = Self(rawValue: 20)
    // MARK: Files and kernel
    public static let closeModified = Self(rawValue: 21), closeFileType = Self(rawValue: 22)
    public static let closeMachOType = Self(rawValue: 23), deleteextattrExtattr = Self(rawValue: 24)
    public static let iokitOpenDriverBundleID = Self(rawValue: 25)
    // MARK: Sockets and XPC
    public static let uipcConnectFileStatUID = Self(rawValue: 26), xpcConnectServiceName = Self(rawValue: 27)
    public static let xpcConnectServiceDomainTypeString = Self(rawValue: 28)
    // MARK: Added in 3.1
    public static let execTargetEUID = Self(rawValue: 29), execTargetRUID = Self(rawValue: 30)
    public static let iokitOpenUserClientClass = Self(rawValue: 31)

    /// Each direct field's key path and kind, by its raw value.
    private static let direct: [(path: String, kind: Kind)] = [
        ("es_event_type", .string), ("context", .string), ("target_path", .string),
        ("process.executable.path", .string), ("process.executable.name", .string), ("process.signing_id", .string),
        ("process.team_id", .string), ("process.is_platform_binary", .boolean), ("process.codesigning_type", .string),
        ("process.is_adhoc_signed", .boolean),
        ("event.exec.command_line", .string), ("event.exec.env", .strings), ("event.exec.script_content", .string),
        ("event.exec.executable_age_ms", .number), ("event.exec.target.signing_id", .string),
        ("event.exec.target.team_id", .string), ("event.exec.target.is_platform_binary", .boolean),
        ("event.exec.target.is_adhoc_signed", .boolean), ("event.exec.target.codesigning_type", .string),
        ("event.exec.target.executable.path", .string), ("event.exec.target.executable.name", .string),
        ("event.close.modified", .boolean), ("event.close.file_type", .string), ("event.close.mach_o_type", .string),
        ("event.deleteextattr.extattr", .string), ("event.iokit_open.driver_bundle_id", .string),
        ("event.uipc_connect.file.stat.st_uid", .number), ("event.xpc_connect.service_name", .string),
        ("event.xpc_connect.service_domain_type_string", .string),
        ("event.exec.target.euid", .number), ("event.exec.target.ruid", .number),
        ("event.iokit_open.user_client_class", .string),
    ]

    /// Each direct field's name, as its static property has it, by its raw value.
    private static let names = [
        "esEventType", "context", "targetPath", "processExecutablePath", "processExecutableName", "processSigningID",
        "processTeamID", "processIsPlatformBinary", "processCodesigningType", "processIsAdhocSigned",
        "execCommandLine", "execEnv", "execScriptContent", "execExecutableAge", "execTargetSigningID",
        "execTargetTeamID", "execTargetIsPlatformBinary", "execTargetIsAdhocSigned", "execTargetCodesigningType",
        "execTargetExecutablePath", "execTargetExecutableName", "closeModified", "closeFileType", "closeMachOType",
        "deleteextattrExtattr", "iokitOpenDriverBundleID", "uipcConnectFileStatUID", "xpcConnectServiceName",
        "xpcConnectServiceDomainTypeString", "execTargetEUID", "execTargetRUID", "iokitOpenUserClientClass",
    ]

    /// The direct fields, in order.
    public static let allCases = (0..<UInt16(direct.count)).map(Self.init(rawValue:))

    /// Is it read with one `switch` to its leaf (``MessageValues``), rather than from the event's encoding?
    public var isDirect: Bool { Int(rawValue) < Self.direct.count }

    /// The record's key path, as a predicate names it: `event.exec.command_line`.
    public var path: String {
        isDirect ? Self.direct[Int(rawValue)].path : RecordFields.shared.descriptor(of: self).path
    }

    /// What the value is.
    public var kind: Kind { isDirect ? Self.direct[Int(rawValue)].kind : RecordFields.shared.descriptor(of: self).kind }

    /// The direct field a predicate's key path names.
    ///
    /// - Parameter path: A record's key path, as in `process.executable.path`.
    /// - Returns: The field, or `nil` when it isn't a direct field. ``record(_:)`` gives a record field.
    public init?(path: String) {
        guard let field = Self.byPath[path] else { return nil }
        self = field
    }

    /// Every direct field, by its key path.
    private static let byPath = Dictionary(allCases.map { ($0.path, $0) }) { first, _ in first }

    /// The field a predicate's key path names: a direct one, or else a record field of the telemetry schema.
    ///
    /// - Parameter path: A record's key path.
    /// - Returns: The field.
    /// - Throws: ``SensorProblem/unservedField(_:)`` for a key path the record doesn't have, and
    ///   ``SensorProblem/unservedKind(_:_:)`` for one whose value can't be compared on its own, such as an object or
    ///   a value inside an array of objects.
    public static func record(_ path: String) throws(SensorProblem) -> IndicatorField {
        if let field = IndicatorField(path: path) { return field }
        switch RecordSchema.lookup(path) {
        case .kind(let kind): return RecordFields.shared.field(path, kind: kind)
        case .unsupported(let reason): throw SensorProblem.unservedKind(path, reason)
        case .absent: throw SensorProblem.unservedField(path)
        }
    }
}


extension IndicatorField: CustomStringConvertible {
    /// A direct field's name, as its static property has it, such as `closeFileType`, or a record field's key path.
    public var description: String {
        isDirect ? Self.names[Int(rawValue)] : path
    }
}


// MARK: - Indicator values
/// A field's value on one event, as a predicate on its record compares it (``MessageValues``), or a predicate's
/// constant.
///
/// A string is a slice of the event's own, so reading one copies nothing. Two values are equal only when they're the
/// same bytes: `==` in a predicate is literal, so an NFD path isn't its NFC spelling.
public enum IndicatorValue: Sendable {
    /// No value: `null` in the record, or a key it doesn't have.
    case null
    /// A string.
    case string(Substring)
    /// A number, and whether it's whole. `true` and `false` are 1 and 0, as `NSNumber` compares them.
    case number(Double, isInteger: Bool)
    /// An array of strings.
    case strings([String])

    /// - Parameter string: A string, or `nil`.
    public init(_ string: String?) {
        self = string.map { .string($0[...]) } ?? .null
    }

    /// - Parameter integer: A whole number, or `nil`.
    public init(_ integer: Int?) {
        self = integer.map { .number(Double($0), isInteger: true) } ?? .null
    }

    /// - Parameter boolean: `true` or `false`, which is the number 1 or 0.
    public init(_ boolean: Bool) {
        self = .number(boolean ? 1 : 0, isInteger: true)
    }

    /// A value as Foundation holds it: a record's, as `JSONSerialization` reads it, or a predicate's constant.
    ///
    /// - Parameter object: `nil` or `NSNull`, a string, a number (a Boolean is one), or an array of strings.
    /// - Returns: The value, or `nil` for anything else, such as an object or an array holding other than strings.
    public init?(object: Any?) {
        switch object {
        case nil, is NSNull:
            self = .null
        case let string as String:
            self = .string(string[...])
        case let number as NSNumber where CFGetTypeID(number) == CFBooleanGetTypeID():
            self = .init(number.boolValue)
        case let number as NSNumber:
            self = .number(number.doubleValue, isInteger: !CFNumberIsFloatType(number))
        case let array as [Any]:
            let strings = array.compactMap { $0 as? String }
            guard strings.count == array.count else { return nil }
            self = .strings(strings)
        default:
            return nil
        }
    }

    /// Is it ``null``?
    public var isNull: Bool {
        if case .null = self { true } else { false }
    }
}

extension IndicatorValue: Equatable {
    /// Byte for byte: strings are equal only when their UTF-8 is, and numbers when they and their wholeness are.
    ///
    /// - Parameters:
    ///   - lhs: A value.
    ///   - rhs: Another.
    /// - Returns: Whether they're the same.
    public static func == (lhs: IndicatorValue, rhs: IndicatorValue) -> Bool {
        switch (lhs, rhs) {
        case (.null, .null):
            true
        case let (.string(left), .string(right)):
            left.utf8.elementsEqual(right.utf8)
        case let (.number(left, leftInteger), .number(right, rightInteger)):
            left == right && leftInteger == rightInteger
        case let (.strings(left), .strings(right)):
            left.count == right.count && zip(left, right).allSatisfy { $0.utf8.elementsEqual($1.utf8) }
        default:
            false
        }
    }
}

extension IndicatorValue: CustomStringConvertible {
    /// As a predicate writes it, so `NSPredicate(format:)` reads it back as the same value: `nil`, `"text"`, `7`,
    /// `0.5` or `{"a", "b"}`.
    public var description: String {
        switch self {
        case .null: "nil"
        case .string(let string): Self.literal(string)
        case .number(let number, true) where number.magnitude < 1e18: String(Int64(number))
        case .number(let number, _): String(number)
        case .strings(let strings): "{" + strings.map { Self.literal($0[...]) }.joined(separator: ", ") + "}"
        }
    }

    /// A string as a predicate's quoted constant: `\`, `"`, a newline, a tab and a carriage return escaped as a
    /// predicate format escapes them, and every other control character as `\uXXXX`, which a predicate format reads
    /// (Swift's `\u{7F}` it doesn't). Anything else is written as it is. NUL alone doesn't read back: a predicate
    /// format ends a string at `\u0000`, as at any spelling of it.
    ///
    /// - Parameter string: The string.
    /// - Returns: The string, quoted and escaped.
    static func literal(_ string: Substring) -> String {
        var literal = "\""
        literal.reserveCapacity(string.utf8.count + 2)
        for scalar in string.unicodeScalars {
            switch scalar {
            case "\\": literal += "\\\\"
            case "\"": literal += "\\\""
            case "\n": literal += "\\n"
            case "\t": literal += "\\t"
            case "\r": literal += "\\r"
            case _ where scalar.properties.generalCategory == .control:
                let hex = String(scalar.value, radix: 16, uppercase: true)
                literal += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
            default: literal.unicodeScalars.append(scalar)
            }
        }
        return literal + "\""
    }
}
