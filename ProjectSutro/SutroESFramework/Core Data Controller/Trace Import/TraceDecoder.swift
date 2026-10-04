//
//  TraceDecoder.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Lenient decoder
/// Decodes any `Decodable` from `JSONSerialization` values, bridging Mac Monitor's export format and `Message`'s
/// `Codable` form for every event type at once.
///
/// The export (`ESMessage.encode(to:)` and the event types' encoders) presents each event rather than encoding its
/// `Message`. The differences are regular, so the types' own `Decodable` conformances can read it given these rules:
/// - A missing key or `null` takes a default by type: `nil` for an optional, `false`, `0`, `""`, `[]`, a new `UUID`, and
///   these, recursively, for a nested type. The export leaves out values the app doesn't keep or show (each artifact's
///   `id`, `argc`, `message_darwin_time`).
/// - A scalar where an object is expected is the object's `_0`: an enum case's payload. If it's a UTC time, it's also
///   `{tv_sec, tv_nsec, tv_usec}` (``ESLogger/utcTimespec(from:)``): the export writes ``TimeSpec`` and ``TimeVal`` as
///   ``TimeSpec/humanFormat()``.
/// - A missing `_0` is the enclosing object itself: the export writes an enum case's payload as `{"exec": {...}}` where
///   `Codable` writes `{"exec": {"_0": {...}}}`.
/// - An enum whose value names none of its cases was flattened into its parent: the value is the payload of the case
///   its key names (`"file": {...}` for ``FilePathUnion/file(_:)``), or, when the value is missing, the parent holds it
///   under the one key that names a case (`"file_path": "..."`). An empty one is the case named `unknown`, if any.
/// - Keys a type doesn't have (derived values such as `name`, `team_id`, or `destination_type_string`) are ignored, and
///   ``renamed`` keys are read under their export spelling.
/// - A value of the wrong JSON type is an error, so the event is skipped and counted rather than imported wrong, except
///   for the objects in ``bridges``, which Mac Monitor keeps as a string.
///
/// Enums with raw values have no default, so they take one from ``fallbacks`` when missing or unknown.
///
/// The same rules read eslogger's JSON, which is `Message`'s `Codable` form without `_0`, `id`s, or Mac Monitor's own
/// fields, with ISO 8601 times. Decoding it ``enriching``, each value that's ``ESEnrichable`` derives Mac Monitor's
/// fields from its Endpoint Security ones as it's decoded, the way the Security Extension does.
struct TraceDecoder: Decoder, SingleValueDecodingContainer {
    /// The value (an `NSDictionary`, `NSArray`, `NSString`, `NSNumber` or `NSNull`), or `nil` if it's missing.
    let value: AnyObject?
    /// The object holding the value, and the value's key in it: where an enum flattened into its parent is read from.
    let parent: NSDictionary?, key: String?
    /// Derive Mac Monitor's fields of each value decoded (see ``ESEnrichable``): the trace doesn't carry them.
    let enriching: Bool
    /// The path to the value's parent, and the value's own key: kept apart so a leaf value never builds its path.
    private let parentPath: [CodingKey], last: CodingKey?
    /// The path to the value.
    var codingPath: [CodingKey] { last.map { parentPath + [$0] } ?? parentPath }
    /// Nothing: the types decoded take no options.
    var userInfo: [CodingUserInfoKey: Any] { [:] }
    
    /// Keys the export spells differently from the `Codable` form, by their `Codable` spelling.
    static let renamed = ["succcess": "success"]
    
    /// eslogger objects that Mac Monitor keeps as the string the Security Extension builds from them, by key: an
    /// `od_group_add` or `od_group_remove` event's `member` (`{member_type, member_value}`) is its type's name, and a
    /// `remote_thread_create` event's `thread_state` (`{flavor, state}`) its flavor's name. `nil` is no value.
    static let bridges: [String: (NSDictionary) -> String?] = [
        "member": { object in
            (object["member_type"] as? NSNumber).map { odMemberTypeName(es_od_member_type_t(rawValue: UInt32(truncatingIfNeeded: $0.int64Value))) }
        },
        "thread_state": { object in
            (object["flavor"] as? NSNumber).flatMap { RemoteThreadCreateEvent.flavorName(thread_state_flavor_t(truncatingIfNeeded: $0.int64Value)) }
        },
    ]
    
    /// Values for raw-value enums when theirs is missing or isn't one of their cases.
    static let fallbacks: [ObjectIdentifier: Any] = [
        ObjectIdentifier(CodeSigningType.self): CodeSigningType.unknown,
        ObjectIdentifier(FileQuarantineType.self): FileQuarantineType.disabled,
    ]
    
    /// - Parameters:
    ///   - value: A `JSONSerialization` value, or `nil` for a missing one.
    ///   - parent: The object holding `value`.
    ///   - key: `value`'s key in `parent`.
    ///   - path: The path to `parent`.
    ///   - last: `value`'s key, as a coding key.
    ///   - enriching: Derive Mac Monitor's fields of each value decoded.
    init(_ value: AnyObject?, in parent: NSDictionary? = nil, at key: String? = nil, path: [CodingKey] = [], last: CodingKey? = nil,
         enriching: Bool = false) {
        self.value = value
        self.parent = parent
        self.key = key
        self.parentPath = path
        self.last = last
        self.enriching = enriching
    }
    
    /// Is the value missing or `null`?
    private var isAbsent: Bool { value == nil || value is NSNull }
    
    /// For an object in ``bridges``: the string it stands for (`nil` for none). `nil` for any other value.
    private var bridged: String?? {
        guard let object = value as? NSDictionary, let bridge = key.flatMap({ Self.bridges[$0] }) else { return nil }
        return .some(bridge(object))
    }
    
    /// The error for a value of the wrong JSON type.
    ///
    /// - Parameter type: The type expected.
    /// - Returns: A type mismatch at this value's path.
    private func mismatch<T>(_ type: T.Type) -> DecodingError {
        let found = value.map { "\(Swift.type(of: $0))" } ?? "nothing"
        return .typeMismatch(type, .init(codingPath: codingPath, debugDescription: "expected \(type), found \(found)"))
    }
    
    /// The value as an object: itself, an empty one if it's missing, or an object holding a scalar (see ``TraceDecoder``).
    func container<Key: CodingKey>(keyedBy type: Key.Type) throws -> KeyedDecodingContainer<Key> {
        switch value {
        case let object as NSDictionary:
            return KeyedDecodingContainer(TraceKeyedContainer<Key>(object, decoder: self))
        case _ where isAbsent:
            return KeyedDecodingContainer(TraceKeyedContainer<Key>(NSDictionary(), decoder: self))
        case is NSArray:
            throw mismatch(NSDictionary.self)
        default:
            let object = NSMutableDictionary(object: value!, forKey: "_0" as NSString)
            if let text = value as? String, let time = ESLogger.utcTimespec(from: text) {
                object.addEntries(from: ["tv_sec": time.tv_sec, "tv_nsec": time.tv_nsec, "tv_usec": time.tv_nsec / 1_000])
            }
            return KeyedDecodingContainer(TraceKeyedContainer<Key>(object, decoder: self))
        }
    }
    
    /// The value as an array: itself, or an empty one if it's missing.
    func unkeyedContainer() throws -> UnkeyedDecodingContainer {
        if isAbsent { return TraceUnkeyedContainer(array: NSArray(), decoder: self) }
        guard let array = value as? NSArray else { throw mismatch(NSArray.self) }
        return TraceUnkeyedContainer(array: array, decoder: self)
    }
    
    /// The value as a single value: this decoder.
    func singleValueContainer() throws -> SingleValueDecodingContainer { self }
    
    // MARK: Single values
    /// Is the value missing, `null`, or a bridged object (see ``bridges``) that stands for nothing?
    func decodeNil() -> Bool { isAbsent || bridged == .some(nil) }
    
    /// The value as a `T`: a `UUID` (a new one if it's missing), a ``fallbacks`` value, or what `T` decodes, enriched when
    /// ``enriching``.
    func decode<T: Decodable>(_ type: T.Type) throws -> T {
        if type == UUID.self { return ((value as? String).flatMap(UUID.init(uuidString:)) ?? UUID()) as! T }
        if let fallback = Self.fallbacks[ObjectIdentifier(type)] {
            return isAbsent ? fallback as! T : (try? T(from: self)) ?? fallback as! T
        }
        let decoded = try T(from: self)
        guard enriching, var enrichable = decoded as? any ESEnrichable else { return decoded }
        enrichable.enrich()
        return enrichable as! T
    }
    
    /// The value as a `Bool`: a number, or `"true"` or `"false"`. Missing is `false`.
    func decode(_ type: Bool.Type) throws -> Bool {
        switch value {
        case let number as NSNumber: return number.boolValue
        case let text as String where Bool(text) != nil: return Bool(text)!
        case _ where isAbsent: return false
        default: throw mismatch(type)
        }
    }
    
    /// The value as a `String`: a string, a number's digits, or a bridged object's string (see ``bridges``). Missing is
    /// `""`.
    func decode(_ type: String.Type) throws -> String {
        switch value {
        case let text as NSString: return text as String
        case let number as NSNumber: return number.stringValue
        case _ where isAbsent: return ""
        default:
            guard case .some(let text) = bridged else { throw mismatch(type) }
            return text ?? ""
        }
    }
    
    /// The value as a `Double` (see ``float()``).
    func decode(_ type: Double.Type) throws -> Double { try float() }
    /// The value as a `Float` (see ``float()``).
    func decode(_ type: Float.Type) throws -> Float { try float() }
    /// The value as an `Int` (see ``integer()``).
    func decode(_ type: Int.Type) throws -> Int { try integer() }
    /// The value as an `Int8` (see ``integer()``).
    func decode(_ type: Int8.Type) throws -> Int8 { try integer() }
    /// The value as an `Int16` (see ``integer()``).
    func decode(_ type: Int16.Type) throws -> Int16 { try integer() }
    /// The value as an `Int32` (see ``integer()``).
    func decode(_ type: Int32.Type) throws -> Int32 { try integer() }
    /// The value as an `Int64` (see ``integer()``).
    func decode(_ type: Int64.Type) throws -> Int64 { try integer() }
    /// The value as a `UInt` (see ``integer()``).
    func decode(_ type: UInt.Type) throws -> UInt { try integer() }
    /// The value as a `UInt8` (see ``integer()``).
    func decode(_ type: UInt8.Type) throws -> UInt8 { try integer() }
    /// The value as a `UInt16` (see ``integer()``).
    func decode(_ type: UInt16.Type) throws -> UInt16 { try integer() }
    /// The value as a `UInt32` (see ``integer()``).
    func decode(_ type: UInt32.Type) throws -> UInt32 { try integer() }
    /// The value as a `UInt64` (see ``integer()``).
    func decode(_ type: UInt64.Type) throws -> UInt64 { try integer() }
    
    /// The value as an integer: a number (truncated to fit, as `UInt64` values written as `Int64` are), or a string of
    /// digits. Missing is 0.
    ///
    /// - Returns: The integer.
    /// - Throws: A type mismatch for any other value.
    private func integer<N: FixedWidthInteger>() throws -> N {
        switch value {
        case let number as NSNumber: return N(exactly: number.int64Value) ?? N(truncatingIfNeeded: number.uint64Value)
        case let text as String where N(text) != nil: return N(text)!
        case _ where isAbsent: return 0
        default: throw mismatch(N.self)
        }
    }
    
    /// The value as a floating-point number: a number, or a string of one. Missing is 0.
    ///
    /// - Returns: The number.
    /// - Throws: A type mismatch for any other value.
    private func float<F: BinaryFloatingPoint>() throws -> F {
        switch value {
        case let number as NSNumber: return F(number.doubleValue)
        case let text as String where Double(text) != nil: return F(Double(text)!)
        case _ where isAbsent: return 0
        default: throw mismatch(F.self)
        }
    }
}
