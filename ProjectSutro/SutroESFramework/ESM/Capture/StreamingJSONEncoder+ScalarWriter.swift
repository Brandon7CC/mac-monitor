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
    struct ScalarWriter: SingleValueEncodingContainer {
        let encoder: StreamingJSONEncoder
        /// How many frames were open when the value started.
        let depth: Int
        /// Where in the buffer the value started.
        let start: Int
        var codingPath: [CodingKey] { [] }
        
        /// May the value be written now?
        private var begin: Bool { encoder.beginScalar(depth: depth, start: start) }
        
        /// Write `null`.
        ///
        /// - Throws: Never: `null` always has a JSON form.
        func encodeNil() throws { if begin { encoder.write(raw: "null" as StaticString) } }
        
        /// Write the value.
        ///
        /// - Parameter value: The value.
        /// - Throws: Never: a Boolean always has a JSON form.
        func encode(_ value: Bool) throws { if begin { encoder.write(bool: value) } }
        
        /// Write the string.
        ///
        /// - Parameter value: The string.
        /// - Throws: Never: a string always has a JSON form.
        func encode(_ value: String) throws { if begin { encoder.write(string: value) } }
        
        /// Write the number.
        ///
        /// - Parameter value: The number.
        /// - Throws: `EncodingError.invalidValue` for NaN or infinity, as `JSONEncoder` throws.
        func encode(_ value: Double) throws { if begin { try encoder.write(floating: value) } }
        
        /// Write the number.
        ///
        /// - Parameter value: The number.
        /// - Throws: `EncodingError.invalidValue` for NaN or infinity, as `JSONEncoder` throws.
        func encode(_ value: Float) throws { if begin { try encoder.write(floating: value) } }
        
        /// Write the integer.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: Int) throws { if begin { encoder.write(integer: value) } }
        
        /// Write the integer.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: Int8) throws { if begin { encoder.write(integer: value) } }
        
        /// Write the integer.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: Int16) throws { if begin { encoder.write(integer: value) } }
        
        /// Write the integer.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: Int32) throws { if begin { encoder.write(integer: value) } }
        
        /// Write the integer.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: Int64) throws { if begin { encoder.write(integer: value) } }
        
        /// Write the integer.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: UInt) throws { if begin { encoder.write(integer: value) } }
        
        /// Write the integer.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: UInt8) throws { if begin { encoder.write(integer: value) } }
        
        /// Write the integer.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: UInt16) throws { if begin { encoder.write(integer: value) } }
        
        /// Write the integer.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: UInt32) throws { if begin { encoder.write(integer: value) } }
        
        /// Write the integer.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: UInt64) throws { if begin { encoder.write(integer: value) } }
        
        /// Write the value.
        ///
        /// - Parameter value: The value.
        /// - Throws: The error encoding the value throws.
        func encode<T: Encodable>(_ value: T) throws { if begin { try encoder.write(value) } }
    }
}
