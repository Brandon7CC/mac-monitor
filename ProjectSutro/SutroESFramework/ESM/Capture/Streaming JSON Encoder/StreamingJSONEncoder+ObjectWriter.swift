//
//  StreamingJSONEncoder+ObjectWriter.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Objects
extension StreamingJSONEncoder {
    /// An object's container. Writes nothing once the object is closed (the value is then left to `JSONEncoder`).
    struct ObjectWriter<Key: CodingKey>: KeyedEncodingContainerProtocol {
        let encoder: StreamingJSONEncoder
        /// The object's frame.
        let frame: FrameReference
        var codingPath: [CodingKey] { [] }
        
        /// Write the member's key, then `null`.
        ///
        /// - Parameter key: The member's key.
        /// - Throws: Never: `null` always has a JSON form.
        func encodeNil(forKey key: Key) throws {
            if encoder.member(key, in: frame) { encoder.write(raw: "null" as StaticString) }
        }
        
        /// Write the member's key, then the value.
        ///
        /// - Parameters:
        ///   - value: The value.
        ///   - key: The member's key.
        /// - Throws: Never: a Boolean always has a JSON form.
        func encode(_ value: Bool, forKey key: Key) throws {
            if encoder.member(key, in: frame) { encoder.write(bool: value) }
        }
        
        /// Write the member's key, then the string.
        ///
        /// - Parameters:
        ///   - value: The string.
        ///   - key: The member's key.
        /// - Throws: Never: a string always has a JSON form.
        func encode(_ value: String, forKey key: Key) throws {
            if encoder.member(key, in: frame) { encoder.write(string: value) }
        }
        
        /// Write the member's key, then the number.
        ///
        /// - Parameters:
        ///   - value: The number.
        ///   - key: The member's key.
        /// - Throws: `EncodingError.invalidValue` for NaN or infinity, as `JSONEncoder` throws.
        func encode(_ value: Double, forKey key: Key) throws {
            if encoder.member(key, in: frame) { try encoder.write(floating: value) }
        }
        
        /// Write the member's key, then the number.
        ///
        /// - Parameters:
        ///   - value: The number.
        ///   - key: The member's key.
        /// - Throws: `EncodingError.invalidValue` for NaN or infinity, as `JSONEncoder` throws.
        func encode(_ value: Float, forKey key: Key) throws {
            if encoder.member(key, in: frame) { try encoder.write(floating: value) }
        }
        
        /// Write the member's key, then the integer.
        ///
        /// - Parameters:
        ///   - value: The integer.
        ///   - key: The member's key.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: Int, forKey key: Key) throws {
            if encoder.member(key, in: frame) { encoder.write(integer: value) }
        }
        
        /// Write the member's key, then the integer.
        ///
        /// - Parameters:
        ///   - value: The integer.
        ///   - key: The member's key.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: Int8, forKey key: Key) throws {
            if encoder.member(key, in: frame) { encoder.write(integer: value) }
        }
        
        /// Write the member's key, then the integer.
        ///
        /// - Parameters:
        ///   - value: The integer.
        ///   - key: The member's key.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: Int16, forKey key: Key) throws {
            if encoder.member(key, in: frame) { encoder.write(integer: value) }
        }
        
        /// Write the member's key, then the integer.
        ///
        /// - Parameters:
        ///   - value: The integer.
        ///   - key: The member's key.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: Int32, forKey key: Key) throws {
            if encoder.member(key, in: frame) { encoder.write(integer: value) }
        }
        
        /// Write the member's key, then the integer.
        ///
        /// - Parameters:
        ///   - value: The integer.
        ///   - key: The member's key.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: Int64, forKey key: Key) throws {
            if encoder.member(key, in: frame) { encoder.write(integer: value) }
        }
        
        /// Write the member's key, then the integer.
        ///
        /// - Parameters:
        ///   - value: The integer.
        ///   - key: The member's key.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: UInt, forKey key: Key) throws {
            if encoder.member(key, in: frame) { encoder.write(integer: value) }
        }
        
        /// Write the member's key, then the integer.
        ///
        /// - Parameters:
        ///   - value: The integer.
        ///   - key: The member's key.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: UInt8, forKey key: Key) throws {
            if encoder.member(key, in: frame) { encoder.write(integer: value) }
        }
        
        /// Write the member's key, then the integer.
        ///
        /// - Parameters:
        ///   - value: The integer.
        ///   - key: The member's key.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: UInt16, forKey key: Key) throws {
            if encoder.member(key, in: frame) { encoder.write(integer: value) }
        }
        
        /// Write the member's key, then the integer.
        ///
        /// - Parameters:
        ///   - value: The integer.
        ///   - key: The member's key.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: UInt32, forKey key: Key) throws {
            if encoder.member(key, in: frame) { encoder.write(integer: value) }
        }
        
        /// Write the member's key, then the integer.
        ///
        /// - Parameters:
        ///   - value: The integer.
        ///   - key: The member's key.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: UInt64, forKey key: Key) throws {
            if encoder.member(key, in: frame) { encoder.write(integer: value) }
        }
        
        /// Write the member's key, then the value.
        ///
        /// - Parameters:
        ///   - value: The value.
        ///   - key: The member's key.
        /// - Throws: The error encoding the value throws.
        func encode<T: Encodable>(_ value: T, forKey key: Key) throws {
            if encoder.member(key, in: frame) { try encoder.write(value) }
        }
        
        /// Write the member's key, then open an object for its value.
        ///
        /// - Parameters:
        ///   - keyType: The nested object's keys.
        ///   - key: The member's key.
        /// - Returns: The nested object's container.
        func nestedContainer<NestedKey: CodingKey>(keyedBy keyType: NestedKey.Type,
                                                   forKey key: Key) -> KeyedEncodingContainer<NestedKey> {
            let nested = encoder.member(key, in: frame) ? encoder.open(isObject: true) : .invalid
            return KeyedEncodingContainer(ObjectWriter<NestedKey>(encoder: encoder, frame: nested))
        }
        
        /// Write the member's key, then open an array for its value.
        ///
        /// - Parameter key: The member's key.
        /// - Returns: The nested array's container.
        func nestedUnkeyedContainer(forKey key: Key) -> UnkeyedEncodingContainer {
            let nested = encoder.member(key, in: frame) ? encoder.open(isObject: false) : .invalid
            return ArrayWriter(encoder: encoder, frame: nested)
        }
        
        /// Not streamed: the value is left to `JSONEncoder`.
        ///
        /// - Returns: An encoder whose containers write nothing.
        func superEncoder() -> Encoder {
            encoder.detachedWriter()
        }
        
        /// Not streamed: the value is left to `JSONEncoder`.
        ///
        /// - Parameter key: The member's key, unused.
        /// - Returns: An encoder whose containers write nothing.
        func superEncoder(forKey key: Key) -> Encoder {
            encoder.detachedWriter()
        }
    }
}
