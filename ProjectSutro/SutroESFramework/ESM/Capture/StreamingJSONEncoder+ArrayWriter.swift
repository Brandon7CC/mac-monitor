//
//  StreamingJSONEncoder+ArrayWriter.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Arrays
extension StreamingJSONEncoder {
    /// An array's container. Writes nothing once the array is closed (the value is then left to `JSONEncoder`).
    struct ArrayWriter: UnkeyedEncodingContainer {
        let encoder: StreamingJSONEncoder
        /// The array's frame.
        let frame: FrameReference
        var codingPath: [CodingKey] { [] }
        /// How many elements it holds so far.
        var count: Int {
            frame.index < encoder.state.pointee.frames.count && encoder.state.pointee.frames[frame.index].id == frame.id
                ? encoder.state.pointee.frames[frame.index].count : 0
        }
        
        /// Write `null` as the next element.
        ///
        /// - Throws: Never: `null` always has a JSON form.
        func encodeNil() throws { if encoder.element(in: frame) { encoder.write(raw: "null" as StaticString) } }
        
        /// Write the next element.
        ///
        /// - Parameter value: The value.
        /// - Throws: Never: a Boolean always has a JSON form.
        func encode(_ value: Bool) throws { if encoder.element(in: frame) { encoder.write(bool: value) } }
        
        /// Write the next element.
        ///
        /// - Parameter value: The string.
        /// - Throws: Never: a string always has a JSON form.
        func encode(_ value: String) throws { if encoder.element(in: frame) { encoder.write(string: value) } }
        
        /// Write the next element.
        ///
        /// - Parameter value: The number.
        /// - Throws: `EncodingError.invalidValue` for NaN or infinity, as `JSONEncoder` throws.
        func encode(_ value: Double) throws { if encoder.element(in: frame) { try encoder.write(floating: value) } }
        
        /// Write the next element.
        ///
        /// - Parameter value: The number.
        /// - Throws: `EncodingError.invalidValue` for NaN or infinity, as `JSONEncoder` throws.
        func encode(_ value: Float) throws { if encoder.element(in: frame) { try encoder.write(floating: value) } }
        
        /// Write the next element.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: Int) throws { if encoder.element(in: frame) { encoder.write(integer: value) } }
        
        /// Write the next element.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: Int8) throws { if encoder.element(in: frame) { encoder.write(integer: value) } }
        
        /// Write the next element.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: Int16) throws { if encoder.element(in: frame) { encoder.write(integer: value) } }
        
        /// Write the next element.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: Int32) throws { if encoder.element(in: frame) { encoder.write(integer: value) } }
        
        /// Write the next element.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: Int64) throws { if encoder.element(in: frame) { encoder.write(integer: value) } }
        
        /// Write the next element.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: UInt) throws { if encoder.element(in: frame) { encoder.write(integer: value) } }
        
        /// Write the next element.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: UInt8) throws { if encoder.element(in: frame) { encoder.write(integer: value) } }
        
        /// Write the next element.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: UInt16) throws { if encoder.element(in: frame) { encoder.write(integer: value) } }
        
        /// Write the next element.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: UInt32) throws { if encoder.element(in: frame) { encoder.write(integer: value) } }
        
        /// Write the next element.
        ///
        /// - Parameter value: The integer.
        /// - Throws: Never: an integer always has a JSON form.
        func encode(_ value: UInt64) throws { if encoder.element(in: frame) { encoder.write(integer: value) } }
        
        /// Write the next element.
        ///
        /// - Parameter value: The value.
        /// - Throws: The error encoding the value throws.
        func encode<T: Encodable>(_ value: T) throws { if encoder.element(in: frame) { try encoder.write(value) } }
        
        /// Open an object as the next element.
        ///
        /// - Parameter keyType: The nested object's keys.
        /// - Returns: The nested object's container.
        func nestedContainer<NestedKey: CodingKey>(
            keyedBy keyType: NestedKey.Type
        ) -> KeyedEncodingContainer<NestedKey> {
            let nested = encoder.element(in: frame) ? encoder.open(isObject: true) : .invalid
            return KeyedEncodingContainer(ObjectWriter<NestedKey>(encoder: encoder, frame: nested))
        }
        
        /// Open an array as the next element.
        ///
        /// - Returns: The nested array's container.
        func nestedUnkeyedContainer() -> UnkeyedEncodingContainer {
            ArrayWriter(encoder: encoder, frame: encoder.element(in: frame) ? encoder.open(isObject: false) : .invalid)
        }
        
        /// Not streamed: the value is left to `JSONEncoder`.
        ///
        /// - Returns: An encoder whose containers write nothing.
        func superEncoder() -> Encoder {
            encoder.detachedWriter()
        }
    }
}
