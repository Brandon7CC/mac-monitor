//
//  Thread.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/7/25.
//

import Foundation

/// Models an `es_thread_t` for a ``Message``
public struct Thread: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID()
    
    public var thread_id: Int
    
    /// A thread as Endpoint Security describes it.
    ///
    /// - Parameter thread: The thread.
    public init(from thread: es_thread_t) {
        self.thread_id = Int(thread.thread_id)
    }
    
    /// The thread that took a message's action.
    ///
    /// `es_message_t.thread` is `_Nullable` and only there from message version 4 (`ESMessage.h`). Endpoint Security
    /// leaves it `NULL` when no thread applies, for example a trace event for a process calling `ptrace(PT_TRACE_ME)`
    /// or a cs_invalidated event caused by another process's `csops(CS_OPS_MARKINVALID)`. eslogger writes `null` then.
    ///
    /// - Parameter message: The message.
    /// - Returns: The thread, or `nil` when the message has none.
    static func of(_ message: es_message_t) -> Thread? {
        guard message.version >= 4, let thread = message.thread else { return nil }
        return Thread(from: thread.pointee)
    }
}
