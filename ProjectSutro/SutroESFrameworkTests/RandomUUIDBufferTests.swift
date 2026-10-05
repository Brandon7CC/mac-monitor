//
//  RandomUUIDBufferTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
import os
@testable import SutroESFramework


// MARK: - Random UUIDs
/// Pins that ``RandomUUIDBuffer`` makes what `UUID()` makes: random version 4 UUIDs with the RFC 4122 variant, never
/// the same twice, from any number of threads at once.
final class RandomUUIDBufferTests: XCTestCase {
    /// Is a UUID version 4, variant RFC 4122?
    ///
    /// - Parameter uuid: The UUID.
    /// - Returns: `true` if its version and variant bits are those of a random UUID.
    private func isRandomVersion4(_ uuid: UUID) -> Bool {
        uuid.uuid.6 >> 4 == 4 && uuid.uuid.8 >> 6 == 0b10
    }
    
    /// Every UUID is version 4 with the RFC 4122 variant, as `UUID()`'s are, across many refills.
    func testVersionAndVariantMatchUUID() {
        XCTAssertTrue(isRandomVersion4(UUID()))
        let buffer = RandomUUIDBuffer()
        for _ in 0..<(RandomUUIDBuffer.capacity / 16 * 8 + 3) {
            XCTAssertTrue(isRandomVersion4(buffer.next()))
        }
    }
    
    /// No UUID repeats, and each of the 122 random bits is set about half the time.
    func testUUIDsAreRandom() {
        let count = 40_000
        var seen = Set<UUID>(minimumCapacity: count)
        var ones = [Int](repeating: 0, count: 128)
        for _ in 0..<count {
            let uuid = UUID.buffered()
            XCTAssertTrue(seen.insert(uuid).inserted)
            withUnsafeBytes(of: uuid.uuid) { bytes in
                for bit in 0..<128 where bytes[bit / 8] >> (7 - bit % 8) & 1 == 1 { ones[bit] += 1 }
            }
        }
        let fixed: Set<Int> = [48, 49, 50, 51, 64, 65]
        for bit in 0..<128 where !fixed.contains(bit) {
            XCTAssertEqual(Double(ones[bit]) / Double(count), 0.5, accuracy: 0.02, "bit \(bit)")
        }
    }
    
    /// Threads taking UUIDs at once get distinct ones.
    func testConcurrentUUIDsAreDistinct() {
        let all = OSAllocatedUnfairLock(initialState: Set<UUID>())
        DispatchQueue.concurrentPerform(iterations: 8) { _ in
            let mine = (0..<20_000).map { _ in UUID.buffered() }
            all.withLock { $0.formUnion(mine) }
        }
        XCTAssertEqual(all.withLock { $0.count }, 160_000)
    }
    
    /// A captured event's models still get distinct random version 4 identifiers.
    func testModelsGetRandomIdentifiers() {
        let message = Message(from: sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: 1).raw)
        for uuid in [message.id, message.process.id] {
            XCTAssertTrue(isRandomVersion4(uuid))
        }
        XCTAssertNotEqual(message.id, message.process.id)
    }
}
