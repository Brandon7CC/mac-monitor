//
//  Message.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/6/22.
//

import Foundation
import EndpointSecurity
import OSLog


/// Models an [`es_message_t`](https://developer.apple.com/documentation/endpointsecurity/es_message_t)  which describes an
/// emitted security event from Endpoint Security.
///
/// Events are emitted by Endpoint Security based on **event subscriptions**. Each event is represented as an optional field in our `ESMessage` structure.
/// For example:
/// * `exec_event` corresponds to an ``ProcessExecEvent`` which notifies us of processes being executed
/// * `iokit_open_event` similarly corresponds to an ``IOKitOpenEvent``. This event notifies us when an IOKit device has been opened.
///
public struct Message: Identifiable, Codable, Hashable {
    public var id = UUID()
    
    /// Version and sequence
    public var version, schema_version: Int
    public var seq_num, global_seq_num: Int?
    
    /// Time
    public var time: String
    public var mach_time: Int64
    public var message_darwin_time: Date = Date()
    
    /// Platform -- Mac Monitor enrichment
    public var macOS: String
    public var sensor_id: String
    
    /// Initiating process
    public var process: Process
    
    /// Thread
    public var thread: Thread
    
    /// Event
    /// A process execution event. Corresponds to `ES_EVENT_TYPE_NOTIFY_EXEC`
    public var event: EventType
    public var event_type: Int
    /// @note Mac Monitor enrichment
    public var es_event_type: String
    
    /// Action
    public var action_type: Int
    /// `ES_ACTION_TYPE_AUTH` vs. `ES_ACTION_TYPE_NOTIFY`
    public var action_type_string: String
    public var action: ActionResultWrapper
    
    /// "context" will be a context item independent of `target_path`
    /// /// @note Mac Monitor enrichment
    public var context: String?
    
    /// `target_path` represents a path "targeted" by some ES event. For example,
    /// * ``MMapEvent`` events will have the `target_path` field set for their `path`
    /// * ``ProcessExecEvent`` events will have the `target_path` field set for their `process_path`
    /// * Similarly, for events like ``FileWriteEvent`` the `target_path` will be set for the file's destination path.
    /// > Not all events will have this populated. For example, it doesn't make sense for ``IOKitOpenEvent`` events to have a target path.
    /// /// @note Mac Monitor enrichment
    public var target_path: String?
    
    
    // MARK: - Protocol Conformance
    public func hash(into hasher: inout Hasher) {
        hasher.combine(event_type)
        hasher.combine(process.audit_token)
        hasher.combine(mach_time)
    }
    
    public static func == (lhs: Message, rhs: Message) -> Bool {
        return lhs.event_type == rhs.event_type &&
               lhs.process.audit_token == rhs.process.audit_token &&
               lhs.mach_time == rhs.mach_time &&
               lhs.event == rhs.event
    }
    
    
    // MARK: - Message init
    init(
        from rawMessage: UnsafePointer<es_message_t>,
        sensorID: String = "SENSOR-ID-NOT-SET",
        archivedFiles: [String] = [],
        forcedQuarantineSigningIDs: [String] = []
    ) {
        let message: es_message_t = rawMessage.pointee
        
        /// Version and sequence
        self.version = Int(message.version)
        self.schema_version = 1 // ESLogger schema version
        if version >= 2 {
            self.seq_num = Int(message.seq_num)
        }
        if version >= 4 {
            self.global_seq_num = Int(message.global_seq_num)
        }
        
        /// Time
        let ats = ProcessHelpers.timespecToTimestamp(timespec: message.time)
        self.time = ProcessHelpers.timestampFormatter.string(from: ats)
        self.mach_time = Int64(message.mach_time)
        self.message_darwin_time = ProcessHelpers.timespecToTimestamp(timespec: message.time)
        
        /// Platform -- Mac Monitor enrichment
        self.sensor_id = sensorID
        self.macOS = String(ProcessInfo.processInfo.operatingSystemVersionString.trimmingPrefix("Version "))
        
        /// Initiating process
        if message.event_type == ES_EVENT_TYPE_NOTIFY_EXEC {
            self.process = Process(
                from: message.process.pointee,
                version: Int(version),
                isExecMessage: true
            )
        } else {
            self.process = Process(from: message.process.pointee, version: Int(rawMessage.pointee.version))
        }
        
        
        /// Thread
        self.thread = Thread(from: message.thread)
        
        
        /// Event
        /// A process execution event. Corresponds to `ES_EVENT_TYPE_NOTIFY_EXEC`
        let (event, eventType, context, targetPath) = EventType.from(
            rawMessage: rawMessage,
            forcedQuarantineSigningIDs: forcedQuarantineSigningIDs
        )

        self.event = event
        self.event_type = Int(message.event_type.rawValue)
        self.es_event_type = eventType
        
        
        /// Action
        self.action_type = Int(message.action_type.rawValue)
        self.action = ActionResultWrapper(from: message)
        /// `ES_ACTION_TYPE_AUTH` vs. `ES_ACTION_TYPE_NOTIFY`
        switch message.action_type {
        /// The result is an auth result
        case ES_ACTION_TYPE_AUTH:
            self.action_type_string = "ES_ACTION_TYPE_AUTH"
        /// The result is a flags result
        case ES_ACTION_TYPE_NOTIFY:
            self.action_type_string = "ES_ACTION_TYPE_NOTIFY"
        default:
            self.action_type_string = "UNKNOWN_ACTION"
            break
        }
        
        /// "context" will be a context item independent of `target_path`
        /// /// @note Mac Monitor enrichment
        self.context = context
        
        
        /// `target_path` represents a path "targeted" by some ES event. For example,
        /// * ``MMapEvent`` events will have the `target_path` field set for their `path`
        /// * ``ProcessExecEvent`` events will have the `target_path` field set for their `process_path`
        /// * Similarly, for events like ``FileWriteEvent`` the `target_path` will be set for the file's destination path.
        /// > Not all events will have this populated. For example, it doesn't make sense for ``IOKitOpenEvent`` events to have a target path.
        /// /// @note Mac Monitor enrichment
        self.target_path = targetPath
    }
}
