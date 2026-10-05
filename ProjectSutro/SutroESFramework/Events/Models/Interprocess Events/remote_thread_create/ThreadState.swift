//
//  ThreadState.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import EndpointSecurity


// MARK: - Thread state
/// A new thread's machine state from a `remote_thread_create` event: an `es_thread_state_t`.
///
/// Its JSON is `eslogger(1)`'s, plus the state's bytes, which eslogger doesn't write:
/// `{"flavor": 6, "state": null, "state_base64": "..."}`. eslogger writes `state` as `null` whatever the event
/// holds (on macOS 27.0, 26A5353q, its `es_thread_state_t` encoder writes `flavor` and then `null`), so Mac Monitor
/// keeps the bytes in its own `state_base64`.
public struct ThreadState: Codable, Hashable {
    /// The state's representation, a `thread_state_flavor_t`, such as 6 for `ARM_THREAD_STATE64` on Apple silicon. What
    /// a flavor stands for depends on the architecture of the Mac that recorded it (see ``ThreadStateFlavor``).
    public var flavor: Int32
    /// The state's bytes (an `es_token_t`) in base64, as eslogger writes an `es_token_t`: `nil` when its `data` is
    /// `NULL`, and `""` when it's empty.
    public var state_base64: String?
    
    /// The most bytes of state kept: `THREAD_STATE_MAX` 32-bit words, the largest state Mach exports.
    static let maxStateSize = Int(THREAD_STATE_MAX) * MemoryLayout<natural_t>.size
    /// The length of ``maxStateSize`` bytes in base64.
    static let maxBase64Length = (maxStateSize + 2) / 3 * 4
    
    /// eslogger's keys, then Mac Monitor's.
    enum CodingKeys: String, CodingKey {
        case flavor, state, state_base64
    }
    
    /// A thread state from its values.
    ///
    /// - Parameters:
    ///   - flavor: The state's flavor.
    ///   - state_base64: The state's bytes in base64, or `nil` if they weren't recorded.
    init(flavor: Int32, state_base64: String?) {
        self.flavor = flavor
        self.state_base64 = state_base64
    }
    
    /// Copy an event's thread state, keeping at most ``maxStateSize`` bytes. The bytes belong to the Endpoint Security
    /// message, so they're copied before the Security Extension's handler returns.
    ///
    /// - Parameter threadState: The event's `es_thread_state_t`.
    init(from threadState: es_thread_state_t) {
        flavor = threadState.flavor
        let token = threadState.state
        state_base64 = token.data.map { data in
            /// `size_t` imports as `Int`, so a size of 2^63 or more reads as negative: it's compared unsigned.
            let count = Int(min(UInt(bitPattern: token.size), UInt(Self.maxStateSize)))
            return Data(bytes: data, count: count).base64EncodedString()
        }
    }
    
    /// The state's bytes, decoded from ``state_base64``: `nil` if they weren't recorded.
    public var stateBytes: Data? {
        state_base64.flatMap { Data(base64Encoded: $0) }
    }
}


// MARK: - Coding
extension ThreadState {
    /// Read `flavor`, and the bytes from Mac Monitor's `state_base64`, or from eslogger's `state` should it ever be a
    /// string.
    ///
    /// The bytes are kept to ``maxStateSize``, as the Security Extension keeps them: a trace can hold any string.
    ///
    /// - Parameter decoder: A `JSONDecoder` (the Security Extension's messages) or ``TraceDecoder`` (a trace).
    /// - Throws: A `DecodingError` when `flavor` is missing or isn't a number.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        flavor = try container.decode(Int32.self, forKey: .flavor)
        let base64 = try container.decodeIfPresent(String.self, forKey: .state_base64)
            ?? (try? container.decodeIfPresent(String.self, forKey: .state))
        state_base64 = base64.flatMap(Self.bounded)
    }
    
    /// Bytes in base64, kept to at most ``maxStateSize``.
    ///
    /// - Parameter base64: The bytes in base64.
    /// - Returns: `base64` when it's no longer than ``maxBase64Length``; otherwise its first ``maxStateSize`` bytes in
    ///   base64, or `nil` if it isn't base64.
    private static func bounded(_ base64: String) -> String? {
        guard base64.utf8.count > maxBase64Length else { return base64 }
        return Data(base64Encoded: base64).map { $0.prefix(maxStateSize).base64EncodedString() }
    }
    
    /// Write eslogger's `flavor` and `state` (always `null`, as eslogger writes it), then Mac Monitor's
    /// `state_base64`.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: The encoder's error.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(flavor, forKey: .flavor)
        try container.encodeNil(forKey: .state)
        try container.encode(state_base64, forKey: .state_base64)
    }
}


// MARK: - Presentation
extension ThreadState {
    /// The state's bytes in uppercase hex, `width` to a row, each row led by its offset: `0010  10 11 12 13`.
    ///
    /// - Parameter width: Bytes per row, at least 1.
    /// - Returns: The rows (none for no bytes), or `nil` if the bytes weren't recorded.
    public func hexRows(width: Int = 16) -> [String]? {
        guard let bytes = stateBytes.map(Array.init) else { return nil }
        let width = max(width, 1)
        return stride(from: 0, to: bytes.count, by: width).map { start in
            let row = bytes[start..<min(start + width, bytes.count)].map { String(format: "%02X", $0) }
            return String(format: "%04lX  ", start) + row.joined(separator: " ")
        }
    }
}
