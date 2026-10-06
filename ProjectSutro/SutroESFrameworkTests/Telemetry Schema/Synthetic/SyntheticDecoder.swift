//
//  SyntheticDecoder.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Synthetic decoder
/// Makes up a value of any `Decodable` type, so the drift tests can export every field of every event without anyone
/// writing a fixture: a field added to a model is filled automatically and reaches the export.
///
/// A full variant fills every optional and gives every array one element; an empty one leaves every optional `nil`
/// (but those Endpoint Security never leaves out: ``SyntheticValues/neverNil``) and every array empty. Values come from
/// ``SyntheticValues`` by type and key, and each value that's ``ESEnrichable`` derives Mac Monitor's fields from its
/// Endpoint Security ones as it's decoded, as File > Open Trace… derives them.
///
/// An enum with associated values decodes as the case the variant names for it (``SyntheticVariant/arms``): one that
/// isn't named fails, and the failure says which.
struct SyntheticDecoder: Decoder {
    /// How the value is filled.
    let variant: SyntheticVariant
    /// The type being decoded, by name: what ``SyntheticValues/neverNil`` and the arms are keyed by.
    let owner: String
    /// The value's key in its parent, if it has one.
    let key: String?
    /// The path to the value.
    let codingPath: [CodingKey]
    /// Nothing: the types decoded take no options.
    var userInfo: [CodingUserInfoKey: Any] { [:] }
    
    /// A decoder for a record.
    ///
    /// - Parameter variant: How the record is filled.
    init(_ variant: SyntheticVariant) {
        self.init(variant: variant, owner: "", key: nil, codingPath: [])
    }
    
    /// - Parameters:
    ///   - variant: How the value is filled.
    ///   - owner: The type being decoded.
    ///   - key: The value's key in its parent.
    ///   - codingPath: The path to the value.
    init(variant: SyntheticVariant, owner: String, key: String?, codingPath: [CodingKey]) {
        self.variant = variant
        self.owner = owner
        self.key = key
        self.codingPath = codingPath
    }
    
    /// The value as an object.
    func container<Key: CodingKey>(keyedBy type: Key.Type) throws -> KeyedDecodingContainer<Key> {
        KeyedDecodingContainer(SyntheticKeyedContainer<Key>(decoder: self))
    }
    
    /// The value as an array: one element when full, none when empty. A dictionary whose keys aren't strings or
    /// integers is an array of its keys and values, so a full one has a key and a value.
    func unkeyedContainer() throws -> UnkeyedDecodingContainer {
        SyntheticUnkeyedContainer(decoder: self, count: variant.full ? (owner.hasPrefix("Dictionary<") ? 2 : 1) : 0)
    }
    
    /// The value as a single value: this decoder.
    func singleValueContainer() throws -> SingleValueDecodingContainer {
        SyntheticSingleValue(decoder: self)
    }
    
    /// Is the value under `key` of the type being decoded `nil`? Only in an empty variant, unless Endpoint Security
    /// never leaves it out, or when the variant leaves the key out on purpose.
    ///
    /// - Parameter key: The key.
    /// - Returns: `true` to decode `nil`.
    func isNil(_ key: String) -> Bool {
        if variant.absent.contains("\(owner).\(key)") || variant.absent.contains("*.\(key)") { return true }
        return !variant.full && !SyntheticValues.neverNil.contains("\(owner).\(key)")
            && !SyntheticValues.neverNil.contains("*.\(key)")
    }
    
    /// A child value's decoder. An array's element and an enum case's payload (`_0`) are made up under the key of the
    /// array or the case, so a `file_path` case's payload is a path.
    ///
    /// - Parameter key: The child's key.
    /// - Returns: The decoder.
    func child(_ key: CodingKey) -> SyntheticDecoder {
        let named = key.intValue == nil && key.stringValue != "_0"
        return SyntheticDecoder(variant: variant, owner: owner, key: named ? key.stringValue : self.key,
                                codingPath: codingPath + [key])
    }
    
    /// Make up a `T` for this value: a value from ``SyntheticValues``, a case of a `CaseIterable` enum, or what `T`
    /// decodes, enriched.
    ///
    /// - Parameter type: The type.
    /// - Returns: The value.
    /// - Throws: `DecodingError` for a value the decoder can't make up.
    func make<T: Decodable>(_ type: T.Type) throws -> T {
        if type == String.self, let key, SyntheticValues.objectKeys.contains(key) {
            throw mismatch(type, "\(key) is an object, not a string")
        }
        if let value = SyntheticValues.value(of: type, forKey: key ?? "", in: variant) {
            guard let typed = value as? T else { throw mismatch(type, "the value table's \(value) isn't one") }
            return typed
        }
        if let cases = type as? any CaseIterable.Type, let value = Self.pick(cases, variant.index) as? T {
            return value
        }
        let decoded = try T(from: SyntheticDecoder(variant: variant, owner: "\(T.self)", key: key,
                                                   codingPath: codingPath))
        guard var enrichable = decoded as? any ESEnrichable else { return decoded }
        enrichable.enrich()
        return enrichable as! T
    }
    
    /// A case of a `CaseIterable` type, chosen by the variant.
    ///
    /// - Parameters:
    ///   - type: The type.
    ///   - index: The variant's index: different variants take different cases.
    /// - Returns: The case.
    private static func pick<C: CaseIterable>(_ type: C.Type, _ index: Int) -> Any {
        let all = Array(C.allCases)
        return all[index % all.count]
    }
    
    /// The error for a value the decoder can't make up.
    ///
    /// - Parameters:
    ///   - type: The type asked for.
    ///   - reason: Why.
    /// - Returns: A type mismatch at this value's path.
    func mismatch<T>(_ type: T.Type, _ reason: String) -> DecodingError {
        .typeMismatch(type, .init(codingPath: codingPath, debugDescription: "\(owner): \(reason)"))
    }
}
