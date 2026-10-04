//
//  ESEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/22.
//
//

import Foundation
import CoreData
import EndpointSecurity

extension ESMessage {
    /// ``event_type`` of `ES_EVENT_TYPE_NOTIFY_EXEC` / `ES_EVENT_TYPE_NOTIFY_FORK` events: the only ones that create a process.
    public static let execEventType = Int32(ES_EVENT_TYPE_NOTIFY_EXEC.rawValue)
    public static let forkEventType = Int32(ES_EVENT_TYPE_NOTIFY_FORK.rawValue)

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESMessage> {
        return NSFetchRequest<ESMessage>(entityName: "ESMessage")
    }
    
    @NSManaged public var id: UUID
    
    /// Version and sequence
    @NSManaged public var version, schema_version: Int32
    @NSManaged public var seq_num, global_seq_num: Int64
    
    /// The audit token of the process this event created (`EXEC` target or `FORK` child), if any.
    @NSManaged public var created_audit_token: String?
    /// The audit token of the process that instigated this event (`process.audit_token_string`). Indexed, so the events a
    /// process went on to cause can be found with ``correlated_array``.
    @NSManaged public var instigator_audit_token: String?
    
    /// Copies of values the event tables show, sort, and filter on, taken from this event's own relationships at insert
    /// time (see ``CoreDataController/insertSystemEvents(messages:completion:)``). Reading them never faults a
    /// relationship, so a table can render or query millions of events. `nil` wherever the source is `nil`.
    ///
    /// - `initiating_*`: `process` (the instigating process) and its `executable`.
    /// - `created_*`: the process this event created: the `EXEC` target, or the `FORK` child.
    @NSManaged public var initiating_path, initiating_name, initiating_euid_human, initiating_signing_id: String?
    @NSManaged public var initiating_pid, initiating_ppid: Int32
    /// `process.parent_audit_token_string`, for process lineage.
    @NSManaged public var instigator_parent_audit_token: String?
    @NSManaged public var created_path, created_name, created_signing_id: String?
    @NSManaged public var created_pid: NSNumber?
    /// `event.exec.command_line`.
    @NSManaged public var exec_command_line: String?
    /// `event.exec.target`'s process group and session (`EXEC` events only), so the "Groups" tab finds a group's events
    /// through an index instead of walking every event's relationships.
    @NSManaged public var exec_group_id, exec_session_id: NSNumber?
    /// The save this event was stored in (see ``CoreDataController/eventsInserted``). Lets a reader that refetches while
    /// events stream in tell which events its fetch already covers.
    @NSManaged public var insert_batch: Int64
    
    /// Time
    @NSManaged public var time: String?
    @NSManaged public var mach_time: Int64
    @NSManaged public var message_darwin_time: Date?
    
    /// Platform -- Mac Monitor enrichment
    @NSManaged public var macOS: String?
    @NSManaged public var sensor_id: String?
    
    /// Initiating process. The row may be shared with other events of the same process.
    @NSManaged public var process: ESProcess
    /// The `id` this event's initiating process had (and exports): ``process`` may be shared, and keeps the `id` of the
    /// first event that stored it.
    @NSManaged public var process_id: UUID?
    
    /// Thread
    @NSManaged public var thread: ESThread
    
    /// Event
    /// A process execution event. Corresponds to `ES_EVENT_TYPE_NOTIFY_EXEC`
    @NSManaged public var event: ESEventType
    @NSManaged public var event_type: Int32
    /// @note Mac Monitor enrichment
    @NSManaged public var es_event_type: String?
    
    /// Action
    @NSManaged public var action_type: Int32
    @NSManaged public var action_type_string: String
    @NSManaged public var actionResultData: Data?
    
    /// "context" will be a context item independent of `target_path`
    /// /// @note Mac Monitor enrichment
    @NSManaged public var context: String?
    
    
    /// `target_path` represents a path "targeted" by some ES event. For example,
    /// * ``MMapEvent`` events will have the `target_path` field set for their `path`
    /// * ``ProcessExecEvent`` events will have the `target_path` field set for their `process_path`
    /// * Similarly, for events like ``FileWriteEvent`` the `target_path` will be set for the file's destination path.
    /// > Not all events will have this populated. For example, it doesn't make sense for ``IOKitOpenEvent`` events to have a target path.
    /// /// @note Mac Monitor enrichment
    @NSManaged public var target_path: String?
    
    
    // MARK: - Correlations
    /// Fill in ``created_audit_token`` and the table columns (``initiating_path`` and friends) from the message this event
    /// was made from. Call once, right after the event is inserted.
    ///
    /// Each value is what this event's relationships store for it (and what reading them returned before rows were
    /// shared), taken from the message so a shared row that's still a fault is never loaded.
    ///
    /// - Parameter message: The message this event was inserted from.
    func denormalize(from message: Message) {
        let process = message.process
        let exec = message.event.exec
        let created: Process? = exec?.target ?? message.event.fork?.child
        /// `ESProcess` stores a token string only when it has the token; reading an unset one returned "".
        created_audit_token = created.map { $0.audit_token?.toString() ?? "" }
        
        initiating_path = process.executable?.path
        initiating_name = process.executable?.name
        initiating_euid_human = process.euid_human
        initiating_signing_id = process.signing_id
        initiating_pid = process.pid
        initiating_ppid = process.ppid
        instigator_parent_audit_token = process.parent_audit_token?.toString() ?? ""
        
        created_path = created?.executable?.path
        created_name = created?.executable?.name
        created_signing_id = exec?.target.signing_id
        created_pid = created.map { NSNumber(value: $0.pid) }
        /// `ESProcessExecEvent` stores a missing command line as "".
        exec_command_line = exec.map { $0.command_line ?? "" }
        exec_group_id = exec.map { NSNumber(value: $0.target.group_id) }
        exec_session_id = exec.map { NSNumber(value: $0.target.session_id) }
    }
    
    /// The events instigated by the process this event created (an `EXEC` target or `FORK` child), newest first.
    ///
    /// Fetched through the indexed ``instigator_audit_token`` each time it's read, rather than stored as a relationship,
    /// so inserting an event never has to load its parent's (potentially huge) set of children (#84). Read it once per
    /// use. Each event's `event` comes with it, since the correlation views sort every event by type. Must be called on
    /// this object's context queue, like any other property.
    public var correlated_array: [ESMessage] {
        guard let request = correlatedRequest, let context = managedObjectContext else { return [] }
        request.sortDescriptors = [NSSortDescriptor(key: "mach_time", ascending: false)]
        request.relationshipKeyPathsForPrefetching = ["event"]
        return (try? context.fetch(request)) ?? []
    }
    
    /// Count ``correlated_array`` without loading it.
    ///
    /// - Returns: The number of events instigated by the process this event created.
    public func correlatedCount() -> Int {
        guard let request = correlatedRequest, let context = managedObjectContext else { return 0 }
        return (try? context.count(for: request)) ?? 0
    }
    
    /// The fetch behind ``correlated_array``: the events whose instigator is the process this event created.
    private var correlatedRequest: NSFetchRequest<ESMessage>? {
        guard let token = created_audit_token else { return nil }
        let request = ESMessage.fetchRequest()
        request.predicate = NSPredicate(format: "instigator_audit_token == %@ AND self != %@", token, self)
        return request
    }
}

extension ESMessage : Identifiable {

}
