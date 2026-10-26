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
    
    /// Every key is there. `decodeNil(forKey:)` says which are `nil`.
    func contains(_ key: Key) -> Bool { true }
    /// Is `key`'s value `nil` (see ``SyntheticDecoder/isNil(_:)``)?
    func decodeNil(forKey key: Key) throws -> Bool { decoder.isNil(key.stringValue) }
    /// `key`'s value as a `T`, for every type the protocol asks for by name too.
    func decode<T: Decodable>(_ type: T.Type, forKey key: Key) throws -> T { try decoder.child(key).make(type) }
    
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
    /// The next element as a `T`, for every type the protocol asks for by name too.
    mutating func decode<T: Decodable>(_ type: T.Type) throws -> T { try next().make(type) }
    
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
/// A made-up single value: ``SyntheticDecoder`` is its own container.
extension SyntheticDecoder: SingleValueDecodingContainer {
    /// Is the value `nil` (see ``isNil(_:)``)?
    func decodeNil() -> Bool { key.map(isNil) ?? false }
    /// The value as a `T`, for every type the protocol asks for by name too.
    func decode<T: Decodable>(_ type: T.Type) throws -> T { try make(type) }
}
