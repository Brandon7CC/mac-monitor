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
    struct ArrayWriter: UnkeyedEncodingContainer, ValueSlot {
        let encoder: StreamingJSONEncoder
        /// The array's frame.
        let frame: FrameReference
        /// How many elements it holds so far.
        var count: Int {
            frame.index < encoder.state.pointee.frames.count && encoder.state.pointee.frames[frame.index].id == frame.id
                ? encoder.state.pointee.frames[frame.index].count : 0
        }
        
        /// Start the next element (``StreamingJSONEncoder/element(in:)``).
        ///
        /// - Returns: `false`, writing nothing, if the array was already closed.
        func begin() -> Bool { encoder.element(in: frame) }
        
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
