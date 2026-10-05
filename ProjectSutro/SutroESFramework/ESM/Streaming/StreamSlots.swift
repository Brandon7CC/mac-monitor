//
//  StreamSlots.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import os


// MARK: - Stream slots
/// Caps how many `macmonitor` streams run at once (Security Extension context). Thread-safe.
///
/// Each stream holds a slot from the moment it asks to start until it closes, keyed by its session's number, so
/// reserving or releasing twice for the same stream never takes or frees a second slot.
public final class StreamSlots {
    /// The most streams at once.
    public let capacity: Int
    /// The sessions holding a slot.
    private let taken = OSAllocatedUnfairLock<Set<UInt64>>(initialState: [])
    
    /// - Parameter capacity: The most streams at once, such as ``SensorXPC/maxCommandLineStreams``.
    public init(capacity: Int) {
        self.capacity = capacity
    }
    
    /// How many slots are taken.
    public var count: Int {
        taken.withLock { $0.count }
    }
    
    /// Take a slot for a session.
    ///
    /// - Parameter session: The session's number.
    /// - Returns: `true` if the session holds a slot now, including one it already held. `false` if every slot is
    ///   taken.
    public func reserve(_ session: UInt64) -> Bool {
        taken.withLock { taken in
            guard !taken.contains(session) else { return true }
            guard taken.count < capacity else { return false }
            taken.insert(session)
            return true
        }
    }
    
    /// Free a session's slot. Does nothing if it holds none.
    ///
    /// - Parameter session: The session's number.
    public func release(_ session: UInt64) {
        _ = taken.withLock { $0.remove(session) }
    }
}
