//
//  ESMessage+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/14/22.
//
//
// References:
// - Codable conformance to NSManagedObject: https://gist.github.com/Akhu/5ea1ecbd652fb269f7c4e7db27bc79cc
//

import Foundation
import CoreData
import EndpointSecurity
import OSLog

import Darwin
import ApplicationServices


@objc(ESMessage)
public class ESMessage: NSManagedObject, Identifiable {
    /// ``event_type`` of `ES_EVENT_TYPE_NOTIFY_EXEC` / `ES_EVENT_TYPE_NOTIFY_FORK` events: the only ones that create a
    /// process.
    public static let execEventType = Int32(ES_EVENT_TYPE_NOTIFY_EXEC.rawValue)
    public static let forkEventType = Int32(ES_EVENT_TYPE_NOTIFY_FORK.rawValue)

    /// A fetch request for events: the events themselves, their object IDs, or (with `propertiesToFetch`) some of
    /// their values.
    ///
    /// - Parameters:
    ///   - result: `ESMessage`, `NSManagedObjectID` or `NSDictionary`, which sets the request's `resultType`.
    ///   - predicate: The events to fetch, or `nil` for every one.
    ///   - sort: Their order.
    ///   - loaded: Load each event's values with it, rather than return it as a fault.
    /// - Returns: The request.
    public static func request<ResultType: NSFetchRequestResult>(_ result: ResultType.Type = ESMessage.self,
                                                                 where predicate: NSPredicate? = nil,
                                                                 sortedBy sort: [NSSortDescriptor] = [],
                                                                 loaded: Bool = false) -> NSFetchRequest<ResultType> {
        let request = NSFetchRequest<ResultType>(entityName: "ESMessage")
        if result == NSManagedObjectID.self { request.resultType = .managedObjectIDResultType }
        if result == NSDictionary.self { request.resultType = .dictionaryResultType }
        request.predicate = predicate
        request.sortDescriptors = sort
        request.returnsObjectsAsFaults = !loaded
        return request
    }
    
    @NSManaged public var id: UUID
    
    /// Version and sequence
    @NSManaged public var version, schema_version: Int32
    @NSManaged public var seq_num, global_seq_num: Int64
    
    /// The audit token of the process this event created (`EXEC` target or `FORK` child), if any.
    @NSManaged public var created_audit_token: String?
    /// The audit token of the process that instigated this event (`process.audit_token_string`). Indexed, so the events
    /// a process went on to cause can be found with ``correlated_array``.
    @NSManaged public var instigator_audit_token: String?
    
    /// Copies of values the event tables show, sort, and filter on, taken from this event's own relationships at insert
    /// time (see ``CoreDataController/insertSystemEvents(messages:completion:)``). Reading them never faults a
    /// relationship, so a table can render or query millions of events. `nil` wherever the source is `nil`.
    ///
    /// - `initiating_*`: `process` (the instigating process) and its `executable`.
    /// - `created_*`: the process this event created, which is the `EXEC` target or the `FORK` child.
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
    /// The save this event was stored in (see ``CoreDataController/eventsInserted``). Lets a reader that refetches
    /// while events stream in tell which events its fetch already covers.
    @NSManaged public var insert_batch: Int64
    /// The event's place in the order events reached the store: the order they arrived from the Security Extension, or
    /// a trace's file order. A save numbers its objects in no particular order, so the store keeps this instead.
    @NSManaged public var insert_order: Int64
    
    /// Time
    @NSManaged public var time: String?
    @NSManaged public var mach_time: Int64
    @NSManaged public var message_darwin_time: Date?
    
    /// Platform -- Mac Monitor enrichment
    @NSManaged public var macOS: String?
    @NSManaged public var sip_status: String?
    @NSManaged public var sensor_id: String?
    
    /// Initiating process. The row may be shared with other events of the same process.
    @NSManaged public var process: ESProcess
    /// The `id` this event's initiating process had (and exports): ``process`` may be shared, and keeps the `id` of the
    /// first event that stored it.
    @NSManaged public var process_id: UUID?
    
    /// Thread
    @NSManaged public var thread: ESThread?
    
    /// Event
    /// A process execution event. Corresponds to `ES_EVENT_TYPE_NOTIFY_EXEC`
    @NSManaged public var event: ESEventType
    @NSManaged public var event_type: Int32
    /// @note Mac Monitor enrichment
    @NSManaged public var es_event_type: String?
    
    /// Action
    @NSManaged public var action_type: Int32
    /// `ES_ACTION_TYPE_AUTH` vs. `ES_ACTION_TYPE_NOTIFY`
    @NSManaged public var action_type_string: String
    @NSManaged public var actionResultData: Data?
    
    /// "context" will be a context item independent of `target_path`
    /// /// @note Mac Monitor enrichment
    @NSManaged public var context: String?
    
    
    /// `target_path` represents a path "targeted" by some ES event. For example,
    /// * ``MMapEvent`` events will have the `target_path` field set for their `path`
    /// * ``ProcessExecEvent`` events will have the `target_path` field set for their `process_path`
    /// * Similarly, for events like ``TargetFileEvent`` the `target_path` will be set for the file's destination path.
    /// > Not all events will have this populated. For example, it doesn't make sense for ``IOKitOpenEvent`` events to
    /// > have a target path.
    /// /// @note Mac Monitor enrichment
    @NSManaged public var target_path: String?

    enum CodingKeys: String, CodingKey {
        // MARK: Version and sequence
        case version
        case schema_version
        /// Mac Monitor's enrichment beside eslogger's `schema_version`: the telemetry schema the record follows
        /// (``TelemetrySchema/version``).
        case telemetry_version
        case seq_num
        case global_seq_num
        
        // MARK: Time
        case time
        case mach_time
        
        // MARK: Platform
        case macOS
        case sip_status
        case sensor_id
        
        // MARK: Process and thread
        case process
        case thread
        
        // MARK: Event
        case event
        case event_type
        case es_event_type
        
        // MARK: Action
        case action_type
        case action
        case action_type_string
        
        // MARK: Context and target path
        case context
        case target_path
    }
    
    public var action: ActionResultWrapper? {
        get {
            guard let data = actionResultData else { return nil }
            return try? JSONDecoder().decode(ActionResultWrapper.self, from: data)
        }
        set {
            guard let newValue = newValue else {
                actionResultData = nil
                return
            }
            actionResultData = try? JSONEncoder().encode(newValue)
        }
    }

    
    // MARK: - Custom Core Data entity creation from ESMessage type
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        self.id = message.id
        
        // MARK: Version and sequence
        self.version = Int32(truncatingIfNeeded: message.version)
        self.schema_version = Int32(truncatingIfNeeded: message.schema_version)
        self.seq_num = Int64(message.seq_num ?? 0)
        self.global_seq_num = Int64(message.global_seq_num ?? 0)
        
        // MARK: Time
        /// eslogger's format even when an older Security Extension sent local time (see
        /// ``ESLogger/time(_:darwinTime:)``).
        self.time = ESLogger.time(message.time, darwinTime: message.message_darwin_time)
        self.mach_time = Int64(message.mach_time)
        self.message_darwin_time = message.message_darwin_time
        
        // MARK: Platform
        self.macOS = message.macOS
        self.sip_status = message.sip_status
        self.sensor_id = message.sensor_id
        
        // MARK: Process and thread
        /// The initiating process is shared with its other events (see ``EventRowCaches``), so the event keeps the
        /// process `id` it exports itself.
        attach(ESProcess.row(for: message.process, version: message.version, in: context),
               to: #keyPath(ESMessage.process))
        self.process_id = message.process.id
        self.thread = message.thread.map { ESThread(from: $0, insertIntoManagedObjectContext: context) }
        
        // MARK: Event
        self.event = ESEventType(
            from: message,
            insertIntoManagedObjectContext: context
        )
        self.event_type = Int32(truncatingIfNeeded: message.event_type)
        self.es_event_type = message.es_event_type
        
        // MARK: Action
        self.action_type = Int32(truncatingIfNeeded: message.action_type)
        self.action_type_string = message.action_type_string
        self.action = message.action
        
        // MARK: Context and target path
        self.context = message.context ?? "Not supported"
        self.target_path = message.target_path ?? "Not supported"
    }
    
    /// Store an event as the event store does: inserted with its instigator's token, its columns
    /// (``denormalize(from:)``) and its place in the store.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - order: Its ``insert_order``.
    ///   - batch: Its ``insert_batch``, or `nil` to leave it for the save to stamp.
    ///   - context: The context to insert it into.
    @discardableResult
    convenience init(storing message: Message, order: Int64, batch: Int64? = nil, in context: NSManagedObjectContext) {
        self.init(from: message, insertIntoManagedObjectContext: context)
        insert_order = order
        if let batch { insert_batch = batch }
        instigator_audit_token = message.process.audit_token_string
        denormalize(from: message)
    }

    // MARK: - Correlations
    /// Fill in ``created_audit_token`` and the table columns (``initiating_path`` and friends) from the message this
    /// event was made from. Call once, right after the event is inserted.
    ///
    /// Each value is what this event's relationships store for it (and what reading them returned before rows were
    /// shared), taken from the message so a shared row that's still a fault is never loaded.
    ///
    /// - Parameter message: The message this event was inserted from.
    func denormalize(from message: Message) {
        let process = message.process
        let exec = message.event.exec
        let created: Process? = exec?.target ?? message.event.fork?.child
        /// `ESProcess` stores a token string only when it has the token. Reading an unset one returned "".
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
    /// Fetched through the indexed ``instigator_audit_token`` each time it's read, rather than stored as a
    /// relationship, so inserting an event never has to load its parent's (potentially huge) set of children (#84).
    /// Read it once per use. Each event's `event` comes with it, since the correlation views sort every event by type.
    /// Must be called on this object's context queue, like any other property.
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
        return ESMessage.request(where: NSPredicate(format: "instigator_audit_token == %@ AND self != %@", token, self))
    }
}

// MARK: - Encodable conformance
extension ESMessage: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        // MARK: Version and sequence
        try container.encode(version, forKey: .version)
        try container.encode(schema_version, forKey: .schema_version)
        try container.encode(TelemetrySchema.version, forKey: .telemetry_version)
        if version >= 2 {
            try container.encode(seq_num, forKey: .seq_num)
        }
        if version >= 4 {
            try container.encode(global_seq_num, forKey: .global_seq_num)
        }
        
        // MARK: Time
        try container.encode(time, forKey: .time)
        try container.encode(mach_time, forKey: .mach_time)
        
        // MARK: Platform
        try container.encode(macOS, forKey: .macOS)
        try container.encode(sip_status, forKey: .sip_status)
        try container.encode(sensor_id, forKey: .sensor_id)
        
        // MARK: Process and thread
        try container.encode(ESProcessRecord(process: process, id: process_id ?? process.id), forKey: .process)
        /// `null` when Endpoint Security named no thread, as eslogger writes it.
        try container.encode(thread, forKey: .thread)
        
        // MARK: Event
        try container.encodeIfPresent(event, forKey: .event)
        try container.encode(event_type, forKey: .event_type)
        try container.encode(es_event_type, forKey: .es_event_type)
        
        // MARK: Action
        try container.encode(action, forKey: .action)
        try container.encode(action_type, forKey: .action_type)
        try container.encode(action_type_string, forKey: .action_type_string)
        
        // MARK: Context and target path
        try container.encode(context, forKey: .context)
        try container.encode(target_path, forKey: .target_path)
    }
}
