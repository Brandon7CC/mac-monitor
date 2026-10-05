//
//  RemoteThreadCreateEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_remote_thread_create_t
/// Models an `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE`: a process created a thread in another process with
/// `thread_create` or `thread_create_running`.
public struct RemoteThreadCreateEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    /// The process the thread was created in.
    public var target: Process
    /// The new thread's state for `thread_create_running`, as eslogger writes it; `nil` for `thread_create`.
    public var thread_state: ThreadState?
    
    /// Mac Monitor enrichment: the name of the state's flavor on the architecture of the Mac that recorded it
    /// (``ThreadStateFlavor``), which Mac Monitor wrote as `thread_state` before 2.2.0.
    public var thread_state_string: String?
    
    /// eslogger's keys, then Mac Monitor's.
    enum CodingKeys: String, CodingKey {
        case id, target, thread_state, thread_state_string
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: RemoteThreadCreateEvent, rhs: RemoteThreadCreateEvent) -> Bool {
        if lhs.target.audit_token_string != rhs.target.audit_token_string {
            return false
        }
        
        if lhs.thread_state != rhs.thread_state {
            return false
        }
        
        return true
    }
    
    /// Record the event of a message from Endpoint Security.
    ///
    /// - Parameter rawMessage: The message.
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_remote_thread_create_t = rawMessage.pointee.event.remote_thread_create
        self.init(target: Process(from: event.target.pointee, version: Int(rawMessage.pointee.version)),
                  threadState: event.thread_state?.pointee)
    }
    
    /// Record an event from its Endpoint Security values.
    ///
    /// - Parameters:
    ///   - target: The process the thread was created in.
    ///   - threadState: The event's `thread_state`, or `nil` when it's `NULL` (`thread_create`). Its bytes are copied.
    init(target: Process, threadState: es_thread_state_t?) {
        self.target = target
        thread_state = threadState.map { ThreadState(from: $0) }
        enrich()
    }
}


// MARK: - Decoding
extension RemoteThreadCreateEvent {
    /// Read the event from eslogger's JSON, an export, or the Security Extension, including those before 2.2.0, which
    /// wrote `thread_state` as its flavor's name, or left it out for a flavor they didn't name.
    ///
    /// - Parameter decoder: The event's decoder.
    /// - Throws: The error decoding a field, such as a thread state whose `flavor` isn't a number.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        target = try container.decode(Process.self, forKey: .target)
        /// A name first: ``TraceDecoder`` reads a string where an object is expected as the object's `_0`, so it would
        /// read a name as flavor 0.
        if let name = try? container.decodeIfPresent(String.self, forKey: .thread_state) {
            thread_state = ThreadStateFlavor.flavor(named: name).map { ThreadState(flavor: $0, state_base64: nil) }
            thread_state_string = name
        } else {
            thread_state = try container.decodeIfPresent(ThreadState.self, forKey: .thread_state)
            thread_state_string = try container.decodeIfPresent(String.self, forKey: .thread_state_string)
        }
    }
}


// MARK: - Mac Monitor enrichment
extension RemoteThreadCreateEvent: ESEnrichable {
    /// Derive the name of the thread state's flavor, on this Mac's architecture.
    public mutating func enrich() {
        thread_state_string = thread_state.flatMap { ThreadStateFlavor.name(of: $0.flavor) }
    }
}
