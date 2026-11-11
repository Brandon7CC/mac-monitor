//
//  RandomUUIDBuffer.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import os


// MARK: - Random UUIDs
/// Random (version 4) UUIDs cut from a buffer of random bytes, for the `id` every event model gets.
///
/// `UUID()` asks corecrypto's DRBG for 16 bytes every time (`uuid_generate_random`), about 0.2 µs, and a captured
/// event builds 20 to 30 models: about a fifth of what was left of a capture lane's work per event. This draws 4 KB at
/// a time from `arc4random_buf`, also a cryptographically secure generator, and sets each UUID's version (4) and
/// variant (RFC 4122) bits as `uuid_generate_random` does, so the identifiers are the same kind of random value.
///
/// **Threading:** safe on any thread. The lock is held only to copy 16 bytes out, and every 256 UUIDs to refill. Every
/// capture lane of every session takes it many times per event, so lanes building events at once wait on each other
/// here: with three threads making UUIDs at once, each took 39 ns rather than 9 ns.
final class RandomUUIDBuffer {
    /// The buffer every model shares.
    static let shared = RandomUUIDBuffer()
    /// How many random bytes are drawn at a time: 256 UUIDs.
    static let capacity = 4_096
    
    /// The random bytes, and the offset of the next UUID's.
    private struct State {
        let bytes: UnsafeMutableRawPointer
        var next: Int
    }
    
    private let state: OSAllocatedUnfairLock<State>
    
    /// An empty buffer, filled on first use.
    init() {
        let bytes = UnsafeMutableRawPointer.allocate(byteCount: Self.capacity, alignment: 16)
        state = OSAllocatedUnfairLock(uncheckedState: State(bytes: bytes, next: Self.capacity))
    }
    
    deinit {
        state.withLockUnchecked { $0.bytes.deallocate() }
    }
    
    /// The next random UUID.
    ///
    /// - Returns: A version 4 UUID, as `UUID()` makes.
    func next() -> UUID {
        var uuid: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        withUnsafeMutableBytes(of: &uuid) { destination in
            state.withLockUnchecked { state in
                if state.next == Self.capacity {
                    arc4random_buf(state.bytes, Self.capacity)
                    state.next = 0
                }
                destination.copyMemory(from: UnsafeRawBufferPointer(start: state.bytes + state.next, count: 16))
                state.next += 16
            }
        }
        uuid.6 = uuid.6 & 0x0F | 0x40
        uuid.8 = uuid.8 & 0x3F | 0x80
        return UUID(uuid: uuid)
    }
}


extension UUID {
    /// A random (version 4) UUID, as `UUID()` makes, cut from ``RandomUUIDBuffer``'s random bytes.
    ///
    /// - Returns: The UUID.
    static func buffered() -> UUID {
        RandomUUIDBuffer.shared.next()
    }
}
