//
//  StreamingJSONEncoder+ScalarWriter.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Scalars
extension StreamingJSONEncoder {
    /// A single value's container: writes the value where it goes. A second value through it, as with `JSONEncoder`,
    /// isn't allowed, and leaves the value to `JSONEncoder`.
    struct ScalarWriter: SingleValueEncodingContainer, ValueSlot {
        let encoder: StreamingJSONEncoder
        /// How many frames were open when the value started.
        let depth: Int
        /// Where in the buffer the value started.
        let start: Int
        
        /// May the value be written now (``StreamingJSONEncoder/beginScalar(depth:start:)``)?
        ///
        /// - Returns: `true` if it has written nothing yet.
        func begin() -> Bool { encoder.beginScalar(depth: depth, start: start) }
    }
}


// MARK: - One value at a time
extension StreamingJSONEncoder {
    /// A container that takes one value at a time: an array's next element (``ArrayWriter``) or a single value
    /// (``ScalarWriter``). Each writes the value only when ``begin()`` lets it.
    protocol ValueSlot {
        /// The encoder whose buffer the value goes to.
        var encoder: StreamingJSONEncoder { get }
        
        /// Start the next value where it goes, or refuse it.
        ///
        /// - Returns: `false`, writing nothing, if the value can't be streamed: it's then left to `JSONEncoder`.
        func begin() -> Bool
    }
}

extension StreamingJSONEncoder.ValueSlot {
    /// Empty, as ``StreamingJSONEncoder/ValueWriter``'s is.
    var codingPath: [CodingKey] { [] }
    
    /// Write `null` as the next value.
    ///
    /// - Throws: Never: `null` always has a JSON form.
    func encodeNil() throws { if begin() { encoder.write(raw: "null" as StaticString) } }
    
    /// Write the next value.
    ///
    /// - Parameter value: The value.
    /// - Throws: Never: a Boolean always has a JSON form.
    func encode(_ value: Bool) throws { if begin() { encoder.write(bool: value) } }
    
    /// Write the next value.
    ///
    /// - Parameter value: The string.
    /// - Throws: Never: a string always has a JSON form.
    func encode(_ value: String) throws { if begin() { encoder.write(string: value) } }
    
    /// Write the next value.
    ///
    /// - Parameter value: The number.
    /// - Throws: `EncodingError.invalidValue` for NaN or infinity, as `JSONEncoder` throws.
    func encode(_ value: Double) throws { if begin() { try encoder.write(floating: value) } }
    
    /// Write the next value.
    ///
    /// - Parameter value: The number.
    /// - Throws: `EncodingError.invalidValue` for NaN or infinity, as `JSONEncoder` throws.
    func encode(_ value: Float) throws { if begin() { try encoder.write(floating: value) } }
    
    /// Write the next value.
    ///
    /// - Parameter value: The integer.
    /// - Throws: Never: an integer always has a JSON form.
    func encode(_ value: Int) throws { if begin() { encoder.write(integer: value) } }
    
    /// Write the next value.
    ///
    /// - Parameter value: The integer.
    /// - Throws: Never: an integer always has a JSON form.
    func encode(_ value: Int8) throws { if begin() { encoder.write(integer: value) } }
    
    /// Write the next value.
    ///
    /// - Parameter value: The integer.
    /// - Throws: Never: an integer always has a JSON form.
    func encode(_ value: Int16) throws { if begin() { encoder.write(integer: value) } }
    
    /// Write the next value.
    ///
    /// - Parameter value: The integer.
    /// - Throws: Never: an integer always has a JSON form.
    func encode(_ value: Int32) throws { if begin() { encoder.write(integer: value) } }
    
    /// Write the next value.
    ///
    /// - Parameter value: The integer.
    /// - Throws: Never: an integer always has a JSON form.
    func encode(_ value: Int64) throws { if begin() { encoder.write(integer: value) } }
    
    /// Write the next value.
    ///
    /// - Parameter value: The integer.
    /// - Throws: Never: an integer always has a JSON form.
    func encode(_ value: UInt) throws { if begin() { encoder.write(integer: value) } }
    
    /// Write the next value.
    ///
    /// - Parameter value: The integer.
    /// - Throws: Never: an integer always has a JSON form.
    func encode(_ value: UInt8) throws { if begin() { encoder.write(integer: value) } }
    
    /// Write the next value.
    ///
    /// - Parameter value: The integer.
    /// - Throws: Never: an integer always has a JSON form.
    func encode(_ value: UInt16) throws { if begin() { encoder.write(integer: value) } }
    
    /// Write the next value.
    ///
    /// - Parameter value: The integer.
    /// - Throws: Never: an integer always has a JSON form.
    func encode(_ value: UInt32) throws { if begin() { encoder.write(integer: value) } }
    
    /// Write the next value.
    ///
    /// - Parameter value: The integer.
    /// - Throws: Never: an integer always has a JSON form.
    func encode(_ value: UInt64) throws { if begin() { encoder.write(integer: value) } }
    
    /// Write the next value.
    ///
    /// - Parameter value: The value.
    /// - Throws: The error encoding the value throws.
    func encode<T: Encodable>(_ value: T) throws { if begin() { try encoder.write(value) } }
}
