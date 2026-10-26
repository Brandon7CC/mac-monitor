//
//  StreamingJSONEncoder+Containers.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Container writers
extension StreamingJSONEncoder {
    // MARK: The encoder a value encodes to
    /// What a value's `encode(to:)` sees: containers that write into the ``StreamingJSONEncoder``'s buffer
    /// (``ObjectWriter``, ``ArrayWriter`` and ``ScalarWriter``).
    ///
    /// `codingPath` is always empty (`JSONEncoder` uses it only in error messages), and `userInfo` is empty, as
    /// `JSONEncoder`'s is by default.
    struct ValueWriter: Encoder {
        let encoder: StreamingJSONEncoder
        /// How many frames were open when the value started: its own container, once opened, is the next.
        let depth: Int
        /// Where in the buffer the value started.
        let start: Int
        var codingPath: [CodingKey] { [] }
        var userInfo: [CodingUserInfoKey: Any] { [:] }
        
        /// The value's object: opened on first use, the same one after that (as `JSONEncoder` gives it).
        ///
        /// - Parameter type: The keys.
        /// - Returns: The container.
        func container<Key: CodingKey>(keyedBy type: Key.Type) -> KeyedEncodingContainer<Key> {
            let frame = encoder.container(at: depth, start: start, isObject: true)
            return KeyedEncodingContainer(ObjectWriter<Key>(encoder: encoder, frame: frame))
        }
        
        /// The value's array: opened on first use, the same one after that.
        ///
        /// - Returns: The container.
        func unkeyedContainer() -> UnkeyedEncodingContainer {
            ArrayWriter(encoder: encoder, frame: encoder.container(at: depth, start: start, isObject: false))
        }
        
        /// The value itself, as one scalar or one nested value.
        ///
        /// - Returns: The container.
        func singleValueContainer() -> SingleValueEncodingContainer {
            ScalarWriter(encoder: encoder, depth: depth, start: start)
        }
    }
}


// MARK: - Unstreamable values
extension StreamingJSONEncoder {
    /// An `Encoder` for what can't be streamed (`superEncoder()`): marks the value for `JSONEncoder`, and drops
    /// whatever is written to it.
    ///
    /// - Returns: An encoder whose containers write nothing.
    func detachedWriter() -> Encoder {
        state.pointee.isUnstreamable = true
        return ValueWriter(encoder: self, depth: .max, start: -1)
    }
}
