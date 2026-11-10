//
//  ReadingThreadPolicy.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - The I/O policy of a read
/// How an event's enrichment reads the files the event names (a mapped library's type, a script's text): without
/// updating a file's access time, and without downloading a dataless file (a File Provider file that isn't on disk),
/// which would wait on its provider. A dataless file's read fails with `EDEADLK` instead.
///
/// Both policies are the calling thread's (`IOPOL_SCOPE_THREAD`), set only for the read and put back after it.
/// Endpoint Security's handler queues run on the process's shared worker threads, so whatever else runs on them later
/// (XPC replies, code signing checks, Core Data) reads as it would have. Setting and putting back both is six system
/// calls, 0.9 µs on an M5 built with -O (`enrich.reading_policy`), paid only by a read: a file type found in a lane's
/// memory reads nothing.
enum ReadingThreadPolicy {
    /// The two policies, and the value each has while reading.
    private static let policies: [(type: Int32, reading: Int32)] = [
        (IOPOL_TYPE_VFS_ATIME_UPDATES, IOPOL_ATIME_UPDATES_OFF),
        (IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_MATERIALIZE_DATALESS_FILES_OFF),
    ]

    /// Run a read with the calling thread's policies set, then put back what they were.
    ///
    /// - Parameter body: The read.
    /// - Returns: What `body` returns.
    /// - Throws: What `body` throws. The policies are put back either way.
    static func whileReading<T>(_ body: () throws -> T) rethrows -> T {
        let saved = policies.map { getiopolicy_np($0.type, IOPOL_SCOPE_THREAD) }
        for policy in policies { setiopolicy_np(policy.type, IOPOL_SCOPE_THREAD, policy.reading) }
        defer {
            /// A policy that couldn't be read (-1) is left as reading set it.
            for (policy, value) in zip(policies, saved) where value >= 0 {
                setiopolicy_np(policy.type, IOPOL_SCOPE_THREAD, value)
            }
        }
        return try body()
    }

    /// Are the calling thread's policies the reading ones?
    static var isApplied: Bool {
        policies.allSatisfy { getiopolicy_np($0.type, IOPOL_SCOPE_THREAD) == $0.reading }
    }
}
