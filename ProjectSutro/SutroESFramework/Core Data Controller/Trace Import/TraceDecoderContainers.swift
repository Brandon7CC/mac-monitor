//
//  TraceDecoderContainers.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Containers
/// A JSON object's keys, for ``TraceDecoder``.
struct TraceKeyedContainer<Key: CodingKey>: KeyedDecodingContainerProtocol {
    /// The object.
    let object: NSDictionary
    /// The decoder of the object, with the object's place in its parent.
    let decoder: TraceDecoder
    /// The path to the object.
    let codingPath: [CodingKey]
    /// For an enum the export flattened into its parent (see ``TraceDecoder``): its one case and payload. Found once,
    /// since every key the object lacks looks here.
    private let flattened: NSDictionary?
    
    /// - Parameters:
    ///   - object: The object.
    ///   - decoder: The decoder of the object.
    init(_ object: NSDictionary, decoder: TraceDecoder) {
        self.object = object
        self.decoder = decoder
        codingPath = decoder.codingPath
        flattened = Self.flattened(object, decoder: decoder)
    }
    
    /// The keys of `object` that `Key` has.
    private static func keys(of object: NSDictionary) -> [Key] { object.allKeys.compactMap { ($0 as? String).flatMap(Key.init(stringValue:)) } }
    
    /// For an enum the export flattened into its parent (see ``TraceDecoder``): its one case and payload.
    ///
    /// - Parameters:
    ///   - object: The object.
    ///   - decoder: The decoder of the object.
    /// - Returns: The case and payload, or `nil` for a dictionary (whose keys take any string) and for an object that has
    ///   one of `Key`'s names.
    private static func flattened(_ object: NSDictionary, decoder: TraceDecoder) -> NSDictionary? {
        guard Key(stringValue: "\u{0}") == nil else { return nil }
        let names = object.keyEnumerator()
        while let name = names.nextObject() as? String { if Key(stringValue: name) != nil { return nil } }
        if object.count > 0, let key = decoder.key, Key(stringValue: key) != nil {
            /// A string under a case's key may be another case's payload (``TraceDecoder/stringCases``).
            let named = decoder.value is NSString ? TraceDecoder.stringCases[key].flatMap { Key(stringValue: $0) } : nil
            return [named?.stringValue ?? key: object]
        }
        if decoder.value == nil, let parent = decoder.parent {
            let cases = parent.filter { ($0.key as? String).flatMap(Key.init(stringValue:)) != nil && !($0.value is NSNull) }
            if cases.count == 1, let (name, payload) = cases.first.map({ ($0.key as! String, $0.value) }) { return [name: payload] }
        }
        return object.count == 0 && Key(stringValue: "unknown") != nil ? ["unknown": NSDictionary()] : nil
    }
    
    /// The object's keys that `Key` has, or the flattened enum's case.
    var allKeys: [Key] {
        let own = Self.keys(of: object)
        return own.isEmpty ? flattened.map(Self.keys(of:)) ?? [] : own
    }
    
    /// Does the object hold `key` (see ``value(of:)``)?
    func contains(_ key: Key) -> Bool { value(of: key) != nil }
    
    /// `key`'s value: under its own name or its export spelling; for `_0`, the object itself; for an enum flattened
    /// into its parent, its payload.
    private func value(of key: Key) -> AnyObject? {
        let name = key.stringValue
        if let value = object.object(forKey: name) ?? TraceDecoder.renamed[name].flatMap(object.object(forKey:)) { return value as AnyObject }
        if name == "_0" { return object }
        /// Every type has an `id` the export leaves out, and no enum has a case of that name.
        return name == "id" ? nil : flattened?.object(forKey: name).map { $0 as AnyObject }
    }
    
    /// The decoder of `key`'s value.
    ///
    /// - Parameter key: The key.
    /// - Returns: A decoder that knows the value's place in this object.
    private func child(_ key: Key) -> TraceDecoder {
        TraceDecoder(value(of: key), in: object, at: key.stringValue, path: codingPath, last: key, enriching: decoder.enriching)
    }
    
    /// Is `key`'s value missing or `null`?
    func decodeNil(forKey key: Key) throws -> Bool { child(key).decodeNil() }
    /// `key`'s value as a `T`.
    func decode<T: Decodable>(_ type: T.Type, forKey key: Key) throws -> T { try child(key).decode(type) }
    /// `key`'s value as a `Bool`.
    func decode(_ type: Bool.Type, forKey key: Key) throws -> Bool { try child(key).decode(type) }
    /// `key`'s value as a `String`.
    func decode(_ type: String.Type, forKey key: Key) throws -> String { try child(key).decode(type) }
    /// `key`'s value as a `Double`.
    func decode(_ type: Double.Type, forKey key: Key) throws -> Double { try child(key).decode(type) }
    /// `key`'s value as a `Float`.
    func decode(_ type: Float.Type, forKey key: Key) throws -> Float { try child(key).decode(type) }
    /// `key`'s value as an `Int`.
    func decode(_ type: Int.Type, forKey key: Key) throws -> Int { try child(key).decode(type) }
    /// `key`'s value as an `Int8`.
    func decode(_ type: Int8.Type, forKey key: Key) throws -> Int8 { try child(key).decode(type) }
    /// `key`'s value as an `Int16`.
    func decode(_ type: Int16.Type, forKey key: Key) throws -> Int16 { try child(key).decode(type) }
    /// `key`'s value as an `Int32`.
    func decode(_ type: Int32.Type, forKey key: Key) throws -> Int32 { try child(key).decode(type) }
    /// `key`'s value as an `Int64`.
    func decode(_ type: Int64.Type, forKey key: Key) throws -> Int64 { try child(key).decode(type) }
    /// `key`'s value as an `UInt`.
    func decode(_ type: UInt.Type, forKey key: Key) throws -> UInt { try child(key).decode(type) }
    /// `key`'s value as an `UInt8`.
    func decode(_ type: UInt8.Type, forKey key: Key) throws -> UInt8 { try child(key).decode(type) }
    /// `key`'s value as an `UInt16`.
    func decode(_ type: UInt16.Type, forKey key: Key) throws -> UInt16 { try child(key).decode(type) }
    /// `key`'s value as an `UInt32`.
    func decode(_ type: UInt32.Type, forKey key: Key) throws -> UInt32 { try child(key).decode(type) }
    /// `key`'s value as an `UInt64`.
    func decode(_ type: UInt64.Type, forKey key: Key) throws -> UInt64 { try child(key).decode(type) }
    
    /// `key`'s value as an object.
    func nestedContainer<N: CodingKey>(keyedBy type: N.Type, forKey key: Key) throws -> KeyedDecodingContainer<N> {
        try child(key).container(keyedBy: type)
    }
    /// `key`'s value as an array.
    func nestedUnkeyedContainer(forKey key: Key) throws -> UnkeyedDecodingContainer { try child(key).unkeyedContainer() }
    /// The object's decoder.
    func superDecoder() throws -> Decoder { decoder }
    /// `key`'s value's decoder.
    func superDecoder(forKey key: Key) throws -> Decoder { child(key) }
}

/// A JSON array's elements, for ``TraceDecoder``.
struct TraceUnkeyedContainer: UnkeyedDecodingContainer {
    /// The array.
    let array: NSArray
    /// The decoder of the array.
    let decoder: TraceDecoder
    /// The path to the array.
    let codingPath: [CodingKey]
    /// The next element's position.
    private(set) var currentIndex = 0
    /// The number of elements.
    var count: Int? { array.count }
    /// Have all the elements been decoded?
    var isAtEnd: Bool { currentIndex >= array.count }
    
    /// - Parameters:
    ///   - array: The array.
    ///   - decoder: The decoder of the array.
    init(array: NSArray, decoder: TraceDecoder) {
        self.array = array
        self.decoder = decoder
        codingPath = decoder.codingPath
    }
    
    /// An element's position, for coding paths.
    private struct Index: CodingKey {
        /// The position.
        let intValue: Int?
        /// The position, in digits.
        var stringValue: String { "\(intValue!)" }
        /// - Parameter intValue: The position.
        init(intValue: Int) { self.intValue = intValue }
        /// Positions have no names.
        init?(stringValue: String) { nil }
    }
    
    /// The decoder of the next element.
    private mutating func next() throws -> TraceDecoder {
        guard !isAtEnd else {
            throw DecodingError.valueNotFound(Any.self, .init(codingPath: codingPath, debugDescription: "no more elements"))
        }
        defer { currentIndex += 1 }
        return TraceDecoder(array.object(at: currentIndex) as AnyObject, path: codingPath, last: Index(intValue: currentIndex),
                            enriching: decoder.enriching)
    }
    
    /// Is the next element `null`? If so, it's decoded.
    mutating func decodeNil() throws -> Bool {
        guard !isAtEnd, array.object(at: currentIndex) is NSNull else { return false }
        currentIndex += 1
        return true
    }
    /// The next element as a `T`.
    mutating func decode<T: Decodable>(_ type: T.Type) throws -> T { try next().decode(type) }
    /// The next element as a `Bool`.
    mutating func decode(_ type: Bool.Type) throws -> Bool { try next().decode(type) }
    /// The next element as a `String`.
    mutating func decode(_ type: String.Type) throws -> String { try next().decode(type) }
    /// The next element as a `Double`.
    mutating func decode(_ type: Double.Type) throws -> Double { try next().decode(type) }
    /// The next element as a `Float`.
    mutating func decode(_ type: Float.Type) throws -> Float { try next().decode(type) }
    /// The next element as an `Int`.
    mutating func decode(_ type: Int.Type) throws -> Int { try next().decode(type) }
    /// The next element as an `Int8`.
    mutating func decode(_ type: Int8.Type) throws -> Int8 { try next().decode(type) }
    /// The next element as an `Int16`.
    mutating func decode(_ type: Int16.Type) throws -> Int16 { try next().decode(type) }
    /// The next element as an `Int32`.
    mutating func decode(_ type: Int32.Type) throws -> Int32 { try next().decode(type) }
    /// The next element as an `Int64`.
    mutating func decode(_ type: Int64.Type) throws -> Int64 { try next().decode(type) }
    /// The next element as an `UInt`.
    mutating func decode(_ type: UInt.Type) throws -> UInt { try next().decode(type) }
    /// The next element as an `UInt8`.
    mutating func decode(_ type: UInt8.Type) throws -> UInt8 { try next().decode(type) }
    /// The next element as an `UInt16`.
    mutating func decode(_ type: UInt16.Type) throws -> UInt16 { try next().decode(type) }
    /// The next element as an `UInt32`.
    mutating func decode(_ type: UInt32.Type) throws -> UInt32 { try next().decode(type) }
    /// The next element as an `UInt64`.
    mutating func decode(_ type: UInt64.Type) throws -> UInt64 { try next().decode(type) }
    
    /// The next element as an object.
    mutating func nestedContainer<N: CodingKey>(keyedBy type: N.Type) throws -> KeyedDecodingContainer<N> {
        try next().container(keyedBy: type)
    }
    /// The next element as an array.
    mutating func nestedUnkeyedContainer() throws -> UnkeyedDecodingContainer { try next().unkeyedContainer() }
    /// The next element's decoder.
    mutating func superDecoder() throws -> Decoder { try next() }
}
