//
//  AllocationCounter.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Allocations
/// Counts the heap allocations one thread makes while a body runs, through `malloc_logger`, the hook libmalloc calls
/// on every allocation for MallocStackLogging. Only the thread that calls ``counting(_:)`` is counted.
///
/// **Threading:** one count at a time, process-wide.
enum AllocationCounter {
    /// libmalloc's hook: the event's type, its zone, size and address arguments, the result, and frames to skip.
    typealias Hook = @convention(c) (UInt32, UInt, UInt, UInt, UInt, UInt32) -> Void

    /// `MALLOC_LOG_TYPE_ALLOCATE`: an allocation, alone or as half of a `realloc`.
    private static let allocate: UInt32 = 2
    /// `malloc_logger`, or `nil` where libmalloc doesn't have one.
    private static let slot = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "malloc_logger")
        .map { $0.assumingMemoryBound(to: Hook?.self) }
    /// The thread being counted.
    private static var counted = pthread_self()
    /// Its allocations so far.
    private static var count = 0

    /// Can this process count allocations?
    static var isAvailable: Bool { slot != nil }

    /// Run a body, counting the allocations this thread makes in it.
    ///
    /// - Parameter body: The work.
    /// - Returns: How many allocations it made, or -1 when they can't be counted.
    /// - Throws: What `body` throws.
    static func counting(_ body: () throws -> Void) rethrows -> Int {
        guard let slot, slot.pointee == nil else {
            try body()
            return -1
        }
        counted = pthread_self()
        count = 0
        slot.pointee = { type, _, _, _, _, _ in
            if type & AllocationCounter.allocate != 0, pthread_equal(pthread_self(), AllocationCounter.counted) != 0 {
                AllocationCounter.count += 1
            }
        }
        defer { slot.pointee = nil }
        try body()
        return count
    }
}
