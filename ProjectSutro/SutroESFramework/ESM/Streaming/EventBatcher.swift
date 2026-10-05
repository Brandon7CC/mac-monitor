//
//  EventBatcher.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import OSLog


// MARK: - Event batcher
/// Buffers a capture session's events and sends them in batches to one reader (Security Extension context): Mac
/// Monitor, or a `macmonitor` stream.
///
/// **Back-pressure:** the reader replies to each batch once it has handled it, and at most
/// ``Limits-swift.struct/maxBatchesInFlight`` batches await a reply. Past that, events wait in memory, and past
/// ``Limits-swift.struct/memoryLimit`` the ``EventOverflow`` policy decides: spill to a backlog (Mac Monitor), or drop
/// and pause the source (`macmonitor`). Once anything is in the backlog, newer events go there too until it drains, so
/// the reader always receives events in order.
///
/// **Threading:** not thread-safe. Make every call on ``queue``, which the flush timer and every delivery completion
/// use too.
public final class EventBatcher {
    /// How a batcher sizes and paces its batches.
    public struct Limits: Equatable {
        /// The most events sent in one batch.
        public var batchSize: Int
        /// How long a partial batch waits before it's sent.
        public var flushDelay: DispatchTimeInterval
        /// The most batches awaiting the reader's reply. Past this, events wait in memory.
        public var maxBatchesInFlight: Int
        /// The most events kept in memory while the reader catches up. Past this, the overflow policy decides.
        public var memoryLimit: Int
        
        /// - Parameters:
        ///   - batchSize: The most events sent in one batch.
        ///   - flushDelay: How long a partial batch waits before it's sent.
        ///   - maxBatchesInFlight: The most batches awaiting the reader's reply.
        ///   - memoryLimit: The most events kept in memory.
        public init(batchSize: Int = 500, flushDelay: DispatchTimeInterval = .milliseconds(100),
                    maxBatchesInFlight: Int, memoryLimit: Int) {
            self.batchSize = batchSize
            self.flushDelay = flushDelay
            self.maxBatchesInFlight = maxBatchesInFlight
            self.memoryLimit = memoryLimit
        }
        
        /// Mac Monitor: ``SensorXPC/maxBatchesInFlight`` batches in flight and 5,000 events in memory, then the spool.
        public static let app = Limits(maxBatchesInFlight: SensorXPC.maxBatchesInFlight, memoryLimit: 5_000)
        
        /// `macmonitor`: 4 batches in flight and 2,000 events in memory (about 10 MB at 4.9 KB an event), then pause.
        public static let commandLine = Limits(maxBatchesInFlight: 4, memoryLimit: 2_000)
    }
    
    /// The queue every call, timer, and completion runs on.
    public let queue: DispatchQueue
    /// Names the reader in the log, such as "Mac Monitor".
    public let label: String
    /// Lifetime counts, logged when the reader goes away.
    public private(set) var counters = EventBatcherCounters()
    /// Is the source paused (``EventOverflow/pause(_:)``)?
    public private(set) var isPaused: Bool = false
    /// Closed for good (``close()``).
    public private(set) var isClosed: Bool = false
    private let limits: Limits
    private let overflowPolicy: EventOverflow
    private let delivery: any EventBatchDelivery
    private let willSend: () -> Void
    /// Events waiting in memory, oldest first.
    private var buffer: [Data] = []
    /// Overflow, such as a spool on disk. Every event in it is newer than every event in `buffer`.
    private var backlog: (any EventBacklog)?
    private var batchesInFlight: Int = 0
    private var isFlushScheduled: Bool = false
    /// Events the backlog couldn't take since the last report.
    private var unreportedDrops: Int = 0
    /// Waiting for everything to be delivered (``drain(completion:)``).
    private var drainCompletions: [() -> Void] = []
    static let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension", category: "EventBatcher")
    
    /// A batcher with nothing buffered.
    ///
    /// - Parameters:
    ///   - queue: The serial queue every call is made on.
    ///   - limits: Batch size and pacing.
    ///   - overflow: What to do with events once the memory buffer is full.
    ///   - delivery: Sends each batch to the reader.
    ///   - willSend: Called on `queue` just before each batch is sent, such as to report the capture session's drops.
    ///   - label: Names the reader in the log.
    public init(queue: DispatchQueue, limits: Limits, overflow: EventOverflow, delivery: any EventBatchDelivery,
                willSend: @escaping () -> Void = {}, label: String) {
        self.queue = queue
        self.limits = limits
        self.overflowPolicy = overflow
        self.delivery = delivery
        self.willSend = willSend
        self.label = label
    }
    
    /// Buffer one serialized event and send it when a batch fills up or ``Limits-swift.struct/flushDelay`` elapses.
    ///
    /// - Parameter event: A serialized event. Ignored once the batcher is closed.
    public func enqueue(_ event: Data) {
        guard !isClosed else { return }
        counters.enqueued += 1
        if backlog == nil && buffer.count < limits.memoryLimit {
            buffer.append(event)
        } else {
            overflow(event)
        }
        
        if buffer.count >= limits.batchSize {
            flush()
        } else if !isFlushScheduled {
            isFlushScheduled = true
            queue.asyncAfter(deadline: .now() + limits.flushDelay) { [weak self] in
                self?.isFlushScheduled = false
                self?.flush()
            }
        }
    }
    
    /// Send everything buffered now, without waiting for the flush delay, and call `completion` once nothing is left in
    /// memory, in the backlog, or awaiting the reader's reply. Events enqueued meanwhile are sent first too.
    ///
    /// - Parameter completion: Called once on ``queue``: right away if the batcher is closed or idle, else once it's
    ///   idle or closes.
    public func drain(completion: @escaping () -> Void) {
        guard !isClosed else { return completion() }
        drainCompletions.append(completion)
        flush()
    }
    
    /// Stop for good: drop what's buffered, release the backlog, ignore replies still on their way, and finish any
    /// drain. Logs the drops not yet reported. Calling it again does nothing.
    public func close() {
        guard !isClosed else { return }
        isClosed = true
        reportDrops()
        buffer = []
        backlog = nil
        finishDrain()
    }
}


// MARK: - Sending
extension EventBatcher {
    /// Send the next batch unless too many are already awaiting the reader's reply.
    ///
    /// Each reply calls back in here, so a backlog drains as fast as the reader takes it. A failed delivery only frees
    /// its slot: the reader is gone, and its owner is about to close the batcher.
    private func flush() {
        guard !isClosed else { return }
        refill()
        guard !buffer.isEmpty, batchesInFlight < limits.maxBatchesInFlight else {
            if buffer.isEmpty && backlog == nil && batchesInFlight == 0 { finishDrain() }
            return
        }
        
        let count = min(buffer.count, limits.batchSize)
        let batch = Array(buffer.prefix(count))
        buffer.removeFirst(count)
        batchesInFlight += 1
        reportDrops()
        willSend()
        delivery.deliver(batch) { [weak self, queue] delivered in
            queue.async { self?.finished(count, delivered: delivered) }
        }
    }
    
    /// Account for a batch the reader replied to, or that was lost, then send the next.
    ///
    /// - Parameters:
    ///   - count: The batch's events.
    ///   - delivered: Did the reader reply?
    private func finished(_ count: Int, delivered: Bool) {
        guard !isClosed else { return }
        batchesInFlight -= 1
        guard delivered else { return }
        counters.delivered += count
        resumeIfCaughtUp()
        flush()
    }
    
    /// Call every ``drain(completion:)`` completion waiting.
    private func finishDrain() {
        let completions = drainCompletions
        drainCompletions = []
        completions.forEach { $0() }
    }
}


// MARK: - Overflow
extension EventBatcher {
    /// Hand an event that doesn't fit in memory to the overflow policy.
    ///
    /// - Parameter event: A serialized event.
    private func overflow(_ event: Data) {
        switch overflowPolicy {
        case .backlog(let makeBacklog):
            spill(event, makingBacklogWith: makeBacklog)
        case .pause(let setPaused):
            counters.dropped += 1
            guard !isPaused else { return }
            isPaused = true
            counters.pauses += 1
            setPaused(true)
            Self.logger.debug("\(self.label, privacy: .public) is \(self.buffer.count) events behind. Pausing capture.")
        }
    }
    
    /// Append an event to the backlog, creating it on first use.
    ///
    /// - Parameters:
    ///   - event: A serialized event.
    ///   - makeBacklog: Creates the backlog.
    private func spill(_ event: Data, makingBacklogWith makeBacklog: () throws -> any EventBacklog) {
        do {
            if backlog == nil {
                backlog = try makeBacklog()
                Self.logger.log("""
                    \(self.label, privacy: .public) is \(self.buffer.count) events behind. Spooling new events to disk.
                    """)
            }
            try backlog?.append(event)
            counters.spooled += 1
        } catch {
            /// Only a full spool, or a disk that refuses the write, loses events. Reported from ``flush()``.
            counters.dropped += 1
            unreportedDrops += 1
        }
    }
    
    /// Move backlogged events back into memory, oldest first, as room frees up. Releases the backlog once it's drained.
    private func refill() {
        guard let backlog, buffer.count < limits.memoryLimit else { return }
        do {
            buffer.append(contentsOf: try backlog.read(upTo: limits.memoryLimit - buffer.count))
        } catch {
            Self.logger.fault("""
                \(self.label, privacy: .public): the event spool is unreadable. \(backlog.count) spooled events are \
                lost: \(error.localizedDescription, privacy: .public)
                """)
            counters.dropped += backlog.count
            self.backlog = nil
            return
        }
        if backlog.count == 0 {
            self.backlog = nil
            Self.logger.log("\(self.label, privacy: .public) caught up. The event spool is drained.")
        }
    }
    
    /// Resume a paused source once the buffer has drained to half the memory limit.
    private func resumeIfCaughtUp() {
        guard isPaused, buffer.count <= limits.memoryLimit / 2, case .pause(let setPaused) = overflowPolicy else {
            return
        }
        isPaused = false
        setPaused(false)
        Self.logger.debug("\(self.label, privacy: .public) caught up. Resuming capture.")
    }
    
    /// Log how many events the backlog couldn't take since the last report.
    private func reportDrops() {
        guard unreportedDrops > 0 else { return }
        Self.logger.fault("""
            \(self.label, privacy: .public): dropped \(self.unreportedDrops) events: the event spool is full or \
            couldn't be written.
            """)
        unreportedDrops = 0
    }
}
