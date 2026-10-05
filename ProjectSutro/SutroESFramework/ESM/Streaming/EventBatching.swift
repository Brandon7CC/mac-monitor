//
//  EventBatching.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Delivery
/// Sends one batch of events to the process reading them, for an ``EventBatcher``.
public protocol EventBatchDelivery: AnyObject {
    /// Send a batch.
    ///
    /// - Parameters:
    ///   - batch: Serialized events, oldest first.
    ///   - completion: Called exactly once, on any thread: `true` once the reader replied, `false` if the batch was
    ///     lost because the reader went away.
    func deliver(_ batch: [Data], completion: @escaping (Bool) -> Void)
}


// MARK: - Backlog
/// Overflow storage for events that don't fit in an ``EventBatcher``'s memory, read back in the order they were
/// written, such as the Security Extension's spool on disk. Only used on its batcher's queue.
public protocol EventBacklog: AnyObject {
    /// The events written but not yet read.
    var count: Int { get }
    
    /// Append one event.
    ///
    /// - Parameter event: A serialized event.
    /// - Throws: If the backlog is full or the write fails. The event is lost.
    func append(_ event: Data) throws
    
    /// Read the oldest events.
    ///
    /// - Parameter limit: The most events to return.
    /// - Returns: The oldest unread events, in order.
    /// - Throws: If the backlog can't be read. Everything still in it is lost.
    func read(upTo limit: Int) throws -> [Data]
}


// MARK: - Overflow
/// What an ``EventBatcher`` does with events once its memory buffer is full.
public enum EventOverflow {
    /// Spill to a backlog, made on first use: lossless until the backlog is full. For Mac Monitor, which saves every
    /// event.
    case backlog(() throws -> any EventBacklog)
    
    /// Drop the event and pause the source (`true`) until the buffer drains to half the memory limit (`false`). For a
    /// `macmonitor` stream, which is live: replaying minutes-old events later helps nobody, and a paused capture
    /// session does no work for events that would be dropped. The reader sees the skipped messages as
    /// `global_seq_num` gaps.
    case pause((_ paused: Bool) -> Void)
}


// MARK: - Counters
/// An ``EventBatcher``'s lifetime counts.
public struct EventBatcherCounters: Equatable, Sendable {
    /// Events handed to the batcher.
    public var enqueued: Int = 0
    /// Events in batches the reader replied to.
    public var delivered: Int = 0
    /// Events that went through the backlog.
    public var spooled: Int = 0
    /// Events lost: the backlog refused or lost them, or the memory buffer was full with the source paused.
    public var dropped: Int = 0
    /// How many times the source was paused.
    public var pauses: Int = 0
    
    /// No events yet.
    public init() {}
}
