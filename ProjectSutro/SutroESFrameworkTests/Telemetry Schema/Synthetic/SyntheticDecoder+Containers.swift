//
//  SyntheticDecoder+Containers.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Objects
/// A made-up object, for ``SyntheticDecoder``: it has every key, and an enum's object has the case its variant names.
struct SyntheticKeyedContainer<Key: CodingKey>: KeyedDecodingContainerProtocol {
    /// The object's decoder.
    let decoder: SyntheticDecoder
    /// The path to the object.
    var codingPath: [CodingKey] { decoder.codingPath }
    
    /// An enum's one case: the arm its variant names. Asked only of enums, so an enum the variant doesn't name has no
    /// keys, and decoding it fails at its path.
    var allKeys: [Key] {
        guard let arm = decoder.variant.arms[decoder.owner], let key = Key(stringValue: arm) else { return [] }
        return [key]
    }
    
    /// Every key is there; `decodeNil(forKey:)` says which are `nil`.
    func contains(_ key: Key) -> Bool { true }
    /// Is `key`'s value `nil` (see ``SyntheticDecoder/isNil(_:)``)?
    func decodeNil(forKey key: Key) throws -> Bool { decoder.isNil(key.stringValue) }
    /// `key`'s value as a `T`.
    func decode<T: Decodable>(_ type: T.Type, forKey key: Key) throws -> T { try decoder.child(key).make(type) }
    /// `key`'s value as a `Bool`.
    func decode(_ type: Bool.Type, forKey key: Key) throws -> Bool { try decoder.child(key).make(type) }
    /// `key`'s value as a `String`.
    func decode(_ type: String.Type, forKey key: Key) throws -> String { try decoder.child(key).make(type) }
    /// `key`'s value as a `Double`.
    func decode(_ type: Double.Type, forKey key: Key) throws -> Double { try decoder.child(key).make(type) }
    /// `key`'s value as a `Float`.
    func decode(_ type: Float.Type, forKey key: Key) throws -> Float { try decoder.child(key).make(type) }
    /// `key`'s value as an `Int`.
    func decode(_ type: Int.Type, forKey key: Key) throws -> Int { try decoder.child(key).make(type) }
    /// `key`'s value as an `Int8`.
    func decode(_ type: Int8.Type, forKey key: Key) throws -> Int8 { try decoder.child(key).make(type) }
    /// `key`'s value as an `Int16`.
    func decode(_ type: Int16.Type, forKey key: Key) throws -> Int16 { try decoder.child(key).make(type) }
    /// `key`'s value as an `Int32`.
    func decode(_ type: Int32.Type, forKey key: Key) throws -> Int32 { try decoder.child(key).make(type) }
    /// `key`'s value as an `Int64`.
    func decode(_ type: Int64.Type, forKey key: Key) throws -> Int64 { try decoder.child(key).make(type) }
    /// `key`'s value as a `UInt`.
    func decode(_ type: UInt.Type, forKey key: Key) throws -> UInt { try decoder.child(key).make(type) }
    /// `key`'s value as a `UInt8`.
    func decode(_ type: UInt8.Type, forKey key: Key) throws -> UInt8 { try decoder.child(key).make(type) }
    /// `key`'s value as a `UInt16`.
    func decode(_ type: UInt16.Type, forKey key: Key) throws -> UInt16 { try decoder.child(key).make(type) }
    /// `key`'s value as a `UInt32`.
    func decode(_ type: UInt32.Type, forKey key: Key) throws -> UInt32 { try decoder.child(key).make(type) }
    /// `key`'s value as a `UInt64`.
    func decode(_ type: UInt64.Type, forKey key: Key) throws -> UInt64 { try decoder.child(key).make(type) }
    
    /// `key`'s value as an object, of the same type: an enum case's payload.
    func nestedContainer<N: CodingKey>(keyedBy type: N.Type, forKey key: Key) throws -> KeyedDecodingContainer<N> {
        try decoder.child(key).container(keyedBy: type)
    }
    /// `key`'s value as an array.
    func nestedUnkeyedContainer(forKey key: Key) throws -> UnkeyedDecodingContainer {
        try decoder.child(key).unkeyedContainer()
    }
    /// The object's decoder.
    func superDecoder() throws -> Decoder { decoder }
    /// `key`'s value's decoder.
    func superDecoder(forKey key: Key) throws -> Decoder { decoder.child(key) }
}


// MARK: - Arrays
/// A made-up array, for ``SyntheticDecoder``: its elements are made up like the array's own value.
struct SyntheticUnkeyedContainer: UnkeyedDecodingContainer {
    /// The array's decoder.
    let decoder: SyntheticDecoder
    /// The number of elements.
    let count: Int?
    /// The path to the array.
    var codingPath: [CodingKey] { decoder.codingPath }
    /// The next element's position.
    private(set) var currentIndex = 0
    /// Have all the elements been decoded?
    var isAtEnd: Bool { currentIndex >= (count ?? 0) }
    
    /// - Parameters:
    ///   - decoder: The array's decoder.
    ///   - count: The number of elements.
    init(decoder: SyntheticDecoder, count: Int) {
        self.decoder = decoder
        self.count = count
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
    
    /// The next element's decoder.
    private mutating func next() -> SyntheticDecoder {
        defer { currentIndex += 1 }
        return decoder.child(Index(intValue: currentIndex))
    }
    
    /// Elements are never `nil`.
    mutating func decodeNil() throws -> Bool { false }
    /// The next element as a `T`.
    mutating func decode<T: Decodable>(_ type: T.Type) throws -> T { try next().make(type) }
    /// The next element as a `Bool`.
    mutating func decode(_ type: Bool.Type) throws -> Bool { try next().make(type) }
    /// The next element as a `String`.
    mutating func decode(_ type: String.Type) throws -> String { try next().make(type) }
    /// The next element as a `Double`.
    mutating func decode(_ type: Double.Type) throws -> Double { try next().make(type) }
    /// The next element as a `Float`.
    mutating func decode(_ type: Float.Type) throws -> Float { try next().make(type) }
    /// The next element as an `Int`.
    mutating func decode(_ type: Int.Type) throws -> Int { try next().make(type) }
    /// The next element as an `Int8`.
    mutating func decode(_ type: Int8.Type) throws -> Int8 { try next().make(type) }
    /// The next element as an `Int16`.
    mutating func decode(_ type: Int16.Type) throws -> Int16 { try next().make(type) }
    /// The next element as an `Int32`.
    mutating func decode(_ type: Int32.Type) throws -> Int32 { try next().make(type) }
    /// The next element as an `Int64`.
    mutating func decode(_ type: Int64.Type) throws -> Int64 { try next().make(type) }
    /// The next element as a `UInt`.
    mutating func decode(_ type: UInt.Type) throws -> UInt { try next().make(type) }
    /// The next element as a `UInt8`.
    mutating func decode(_ type: UInt8.Type) throws -> UInt8 { try next().make(type) }
    /// The next element as a `UInt16`.
    mutating func decode(_ type: UInt16.Type) throws -> UInt16 { try next().make(type) }
    /// The next element as a `UInt32`.
    mutating func decode(_ type: UInt32.Type) throws -> UInt32 { try next().make(type) }
    /// The next element as a `UInt64`.
    mutating func decode(_ type: UInt64.Type) throws -> UInt64 { try next().make(type) }
    
    /// The next element as an object.
    mutating func nestedContainer<N: CodingKey>(keyedBy type: N.Type) throws -> KeyedDecodingContainer<N> {
        try next().container(keyedBy: type)
    }
    /// The next element as an array.
    mutating func nestedUnkeyedContainer() throws -> UnkeyedDecodingContainer { try next().unkeyedContainer() }
    /// The next element's decoder.
    mutating func superDecoder() throws -> Decoder { next() }
}


// MARK: - Single values
/// A made-up single value, for ``SyntheticDecoder``.
struct SyntheticSingleValue: SingleValueDecodingContainer {
    /// The value's decoder.
    let decoder: SyntheticDecoder
    /// The path to the value.
    var codingPath: [CodingKey] { decoder.codingPath }
    
    /// Is the value `nil` (see ``SyntheticDecoder/isNil(_:)``)?
    func decodeNil() -> Bool { decoder.key.map(decoder.isNil) ?? false }
    /// The value as a `T`.
    func decode<T: Decodable>(_ type: T.Type) throws -> T { try decoder.make(type) }
    /// The value as a `Bool`.
    func decode(_ type: Bool.Type) throws -> Bool { try decoder.make(type) }
    /// The value as a `String`.
    func decode(_ type: String.Type) throws -> String { try decoder.make(type) }
    /// The value as a `Double`.
    func decode(_ type: Double.Type) throws -> Double { try decoder.make(type) }
    /// The value as a `Float`.
    func decode(_ type: Float.Type) throws -> Float { try decoder.make(type) }
    /// The value as an `Int`.
    func decode(_ type: Int.Type) throws -> Int { try decoder.make(type) }
    /// The value as an `Int8`.
    func decode(_ type: Int8.Type) throws -> Int8 { try decoder.make(type) }
    /// The value as an `Int16`.
    func decode(_ type: Int16.Type) throws -> Int16 { try decoder.make(type) }
    /// The value as an `Int32`.
    func decode(_ type: Int32.Type) throws -> Int32 { try decoder.make(type) }
    /// The value as an `Int64`.
    func decode(_ type: Int64.Type) throws -> Int64 { try decoder.make(type) }
    /// The value as a `UInt`.
    func decode(_ type: UInt.Type) throws -> UInt { try decoder.make(type) }
    /// The value as a `UInt8`.
    func decode(_ type: UInt8.Type) throws -> UInt8 { try decoder.make(type) }
    /// The value as a `UInt16`.
    func decode(_ type: UInt16.Type) throws -> UInt16 { try decoder.make(type) }
    /// The value as a `UInt32`.
    func decode(_ type: UInt32.Type) throws -> UInt32 { try decoder.make(type) }
    /// The value as a `UInt64`.
    func decode(_ type: UInt64.Type) throws -> UInt64 { try decoder.make(type) }
}
