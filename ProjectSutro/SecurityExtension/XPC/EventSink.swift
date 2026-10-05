//
//  EventSink.swift
//  SecurityExtension
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Event sink
/// The Mac Monitor connection that receives events, plus the events waiting to be sent to it: the oldest in memory, any
/// overflow in a spool file. Only touched on `SensorService`'s queue.
final class EventSink {
    let connection: NSXPCConnection
    /// Events waiting in memory, oldest first.
    var buffer: [Data] = []
    /// Overflow on disk. Every event in it is newer than every event in `buffer`.
    var spool: EventSpool?
    var batchesInFlight: Int = 0
    /// Lifetime counters, logged when the sink goes away.
    var enqueuedEvents: Int = 0, spooledEvents: Int = 0, deliveredEvents: Int = 0
    /// Events the spool couldn't take since the last report.
    var droppedEvents: Int = 0
    var isFlushScheduled: Bool = false
    
    /// - Parameter connection: The connection that called `start(recording:reply:)`.
    init(connection: NSXPCConnection) {
        self.connection = connection
    }
}
