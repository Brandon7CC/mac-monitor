//
//  EventStore.swift
//  SutroESFramework
//
//  High-performance event store replacing Core Data.
//
//  Architecture:
//  - Lightweight index (EventIndexEntry) stored in memory for O(1) lookups
//  - Full events stored in memory-mapped binary log (MMAP)
//  - Lazy decode from MMAP only when events are needed for display
//  - Dictionary indices for O(1) correlation lookups
//
//  This eliminates:
//  - The entire Core Data stack (NSManagedObjectContext, NSPersistentContainer, change tracking)
//  - The duplicate model layer (ESMessage, ESProcess, ESEventType, etc.)
//  - Loading all events into memory on startup
//

import Foundation
import OSLog
import Combine
import AppKit
import UniformTypeIdentifiers
import CryptoKit

/// Lightweight index entry for an event stored in the MMAP log.
///
/// Contains only the fields needed for filtering, correlation, and indexing.
/// Full event data is decoded lazily from the MMAP file when needed.
public struct EventIndexEntry {
    public let id: UUID
    public let mmapOffset: Int
    public let machTime: Int64
    public let darwinTime: Date
    public let eventType: Int
    public let esEventType: String
    public let hasExec: Bool
    
    public let auditTokenString: String
    public let parentAuditTokenString: String
    public let groupID: Int32
    public let sessionID: Int32
    public let executablePathHash: UInt64
    public let euidHuman: String?
    public let targetPathHash: UInt64?
    
    public let targetAuditTokenString: String?
    public let targetGroupID: Int32?
    public let targetSessionID: Int32?
    
    init(message: Message, mmapOffset: Int) {
        self.id = message.id
        self.mmapOffset = mmapOffset
        self.machTime = message.mach_time
        self.darwinTime = message.message_darwin_time
        self.eventType = message.event_type
        self.esEventType = message.es_event_type
        self.hasExec = (message.event.exec != nil)
        
        self.auditTokenString = message.process.audit_token_string
        self.parentAuditTokenString = message.process.parent_audit_token_string
        self.groupID = message.process.group_id
        self.sessionID = message.process.session_id
        
        if let path = message.process.executable?.path {
            self.executablePathHash = Self.hashPath(path)
        } else {
            self.executablePathHash = 0
        }
        
        self.euidHuman = message.process.euid_human
        
        if let targetPath = message.target_path {
            self.targetPathHash = Self.hashPath(targetPath)
        } else {
            self.targetPathHash = nil
        }
        
        if let exec = message.event.exec {
            self.targetAuditTokenString = exec.target.audit_token_string
            self.targetGroupID = exec.target.group_id
            self.targetSessionID = exec.target.session_id
        } else if let fork = message.event.fork {
            self.targetAuditTokenString = fork.child.audit_token_string
            self.targetGroupID = fork.child.group_id
            self.targetSessionID = fork.child.session_id
        } else {
            self.targetAuditTokenString = nil
            self.targetGroupID = nil
            self.targetSessionID = nil
        }
    }
    
    private static func hashPath(_ path: String) -> UInt64 {
        let data = Data(path.utf8)
        let hash = SHA256.hash(data: data)
        return hash.withUnsafeBytes { $0.load(as: UInt64.self) }
    }
}

/// High-performance event store that replaces `CoreDataController` and the Core Data stack.
///
/// Uses a lightweight index for fast filtering and correlation, with full events
/// stored in a memory-mapped binary log. Events are decoded lazily only when needed,
/// keeping memory usage constant regardless of event count.
public final class EventStore: ObservableObject {
    public static let shared = EventStore()
    private static let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "EventStore")

    // MARK: - Published state for SwiftUI

    /// Total event count for UI observation. Updated on main thread.
    @Published public private(set) var eventCount: Int = 0

    /// Compatibility shim — intentionally left empty. Use `getEvent(at:)` or `getEventsWindow(_:offset:limit:)` instead.
    @Published public private(set) var events: [Message] = []

    // MARK: - Index storage (storeQueue only)

    /// Lightweight index entries for all events.
    private var index: [EventIndexEntry] = []
    
    /// Reverse lookup: path hash → path string (for lineage resolution).
    private var pathHashLookup: [UInt64: String] = [:]

    /// Timer used to coalesce rapid inserts into a single SwiftUI update.
    private var _publishTimer: DispatchSourceTimer?

    // MARK: - Correlation indices (storeQueue only)

    /// Maps audit_token_string → array indices of events whose *target process*
    /// matches that token (EXEC target or FORK child).
    private var targetAuditTokenIndex: [String: [Int]] = [:]

    /// Maps event UUID → array index for O(1) lookup by ID.
    private var eventIDIndex: [UUID: Int] = [:]

    /// Maps group_id → array indices for process group queries.
    private var processGroupIndex: [Int32: [Int]] = [:]

    /// Maps session_id → array indices for session group queries.
    private var sessionGroupIndex: [Int32: [Int]] = [:]

    // MARK: - Correlation relationships (storeQueue only)

    /// Maps event index → indices of child events.
    private var correlatedChildren: [Int: [Int]] = [:]

    // MARK: - MMAP backing

    /// The memory-mapped binary log.
    private let mmapLog: MMapEventLog

    // MARK: - Thread safety

    /// Concurrent queue for thread-safe access to index and indices.
    /// Reads use `.sync` (concurrent), writes use `.async(flags: .barrier)`.
    private let storeQueue = DispatchQueue(label: "com.swiftlydetecting.agent.eventstore", attributes: .concurrent)

    // MARK: - Init

    public init() {
        do {
            let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
                ?? FileManager.default.temporaryDirectory
            let logDir = appSupport
                .appendingPathComponent("com.swiftlydetecting.agent", isDirectory: true)
                .appendingPathComponent("event_log", isDirectory: true)
            let logURL = logDir.appendingPathComponent("events.mmap")

            mmapLog = try MMapEventLog(url: logURL)
            EventStore.logger.info("MMAP event log initialized at \(logURL.path)")

            try mmapLog.reset()
            EventStore.logger.info("Cleared MMAP log for fresh session")
        } catch {
            fatalError("EventStore requires MMAP backing: \(error)")
        }
    }

    // MARK: - Mutators

    /// Inserts a batch of events with automatic correlation.
    ///
    /// This is the primary ingestion path, replacing `CoreDataController.insertSystemSystems()`.
    ///
    /// 1. Appends all events to the MMAP log in a single batch
    /// 2. Builds index entries for the new events
    /// 3. Correlates new events with their parent processes
    ///
    /// - Parameter messages: The events to insert.
    public func insertEvents(_ messages: [Message]) {
        guard !messages.isEmpty else { return }

        storeQueue.async(flags: .barrier) { [self] in
            let startIndex = index.count
            index.reserveCapacity(index.count + messages.count)

            // Phase 1: Batch append to MMAP (single syscall)
            let offsets: [(offset: Int, message: Message)]
            do {
                offsets = try mmapLog.appendEvents(messages)
            } catch {
                EventStore.logger.error("Failed to batch append events: \(error)")
                return
            }

            // Phase 2: Build index entries
            for (mmapOffset, message) in offsets {
                let entry = EventIndexEntry(message: message, mmapOffset: mmapOffset)
                index.append(entry)
                indexEvent(entry, at: index.count - 1)
            }

            // Phase 3: Correlate new events with parents
            for i in startIndex..<index.count {
                let entry = index[i]
                let parentToken = entry.auditTokenString

                if let parentIndices = targetAuditTokenIndex[parentToken],
                   let parentIndex = parentIndices.last, parentIndex != i {
                    correlatedChildren[parentIndex, default: []].append(i)
                }
            }

            schedulePublish()
        }
    }

    /// Schedules a batched publish to the main thread (call only from `storeQueue`).
    private func schedulePublish() {
        guard _publishTimer == nil else { return }

        let timer = DispatchSource.makeTimerSource(queue: storeQueue)
        timer.schedule(deadline: .now() + 0.05)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.storeQueue.async(flags: .barrier) {
                let count = self.index.count
                self._publishTimer = nil
                DispatchQueue.main.async {
                    self.eventCount = count
                }
            }
        }
        _publishTimer = timer
        timer.resume()
    }

    /// Removes all events and resets indices.
    public func clearEvents() {
        storeQueue.sync(flags: .barrier) {
            index.removeAll(keepingCapacity: true)
            pathHashLookup.removeAll(keepingCapacity: true)
            _publishTimer?.cancel()
            _publishTimer = nil
            targetAuditTokenIndex.removeAll(keepingCapacity: true)
            eventIDIndex.removeAll(keepingCapacity: true)
            processGroupIndex.removeAll(keepingCapacity: true)
            sessionGroupIndex.removeAll(keepingCapacity: true)
            correlatedChildren.removeAll(keepingCapacity: true)
            try? mmapLog.reset()
        }

        DispatchQueue.main.async {
            self.eventCount = 0
        }
    }

    // MARK: - Lazy decode

    /// Decodes and returns the event at the given index position.
    ///
    /// - Parameter index: The index position in the index array.
    /// - Returns: The decoded `Message`, or `nil` if the index is invalid or decode fails.
    public func getEvent(at index: Int) -> Message? {
        return storeQueue.sync {
            guard index >= 0, index < self.index.count else { return nil }
            let entry = self.index[index]
            return try? mmapLog.readEvent(at: entry.mmapOffset)
        }
    }

    /// Decodes and returns events in the given index range.
    ///
    /// - Parameter range: The range of index positions.
    /// - Returns: Array of decoded `Message` values.
    public func getEvents(range: Range<Int>) -> [Message] {
        return storeQueue.sync {
            guard range.lowerBound >= 0, range.upperBound <= index.count else { return [] }
            return range.compactMap { i in
                let entry = index[i]
                return try? mmapLog.readEvent(at: entry.mmapOffset)
            }
        }
    }

    /// Decodes and returns a window of events for table view pagination.
    ///
    /// - Parameters:
    ///   - indices: The index positions to decode.
    /// - Returns: Array of decoded `Message` values.
    public func getEventsWindow(_ indices: [Int]) -> [Message] {
        return storeQueue.sync {
            return indices.compactMap { i in
                guard i >= 0, i < index.count else { return nil }
                let entry = index[i]
                return try? mmapLog.readEvent(at: entry.mmapOffset)
            }
        }
    }

    /// Returns all indices matching the given filter criteria.
    ///
    /// This is a fast path for filtering without decoding events.
    ///
    /// - Parameters:
    ///   - excludedEventTypes: Event type strings to exclude.
    ///   - excludedUserIDs: User IDs to exclude.
    ///   - excludedInitiatingPathHashes: Hashes of initiating paths to exclude.
    ///   - excludedTargetPathHashes: Hashes of target paths to exclude.
    /// - Returns: Array of index positions matching the criteria.
    public func getFilteredIndices(
        excludedEventTypes: Set<String> = [],
        excludedUserIDs: Set<String> = [],
        excludedInitiatingPathHashes: Set<UInt64> = [],
        excludedTargetPathHashes: Set<UInt64> = []
    ) -> [Int] {
        return storeQueue.sync {
            return index.enumerated().compactMap { (i, entry) in
                if excludedEventTypes.contains(entry.esEventType) { return nil }
                if let user = entry.euidHuman, excludedUserIDs.contains(user) { return nil }
                if excludedInitiatingPathHashes.contains(entry.executablePathHash) { return nil }
                if let targetHash = entry.targetPathHash, excludedTargetPathHashes.contains(targetHash) { return nil }
                return i
            }
        }
    }

    /// Returns a snapshot of all index entries.
    ///
    /// Used for index-based filtering and lineage resolution without decoding events.
    public func getIndexSnapshot() -> [EventIndexEntry] {
        return storeQueue.sync { index }
    }

    /// Returns the current number of indexed events.
    public func getIndexCount() -> Int {
        return storeQueue.sync { index.count }
    }

    /// Returns index entries for the requested range.
    public func getIndexEntries(range: Range<Int>) -> [EventIndexEntry] {
        return storeQueue.sync {
            guard range.lowerBound >= 0, range.upperBound <= index.count else { return [] }
            return Array(index[range])
        }
    }
    
    /// Returns the path string for a given path hash.
    public func getPath(forHash hash: UInt64) -> String? {
        guard hash != 0 else { return nil }

        if let cached = storeQueue.sync(execute: { pathHashLookup[hash] }) {
            return cached
        }

        return storeQueue.sync(flags: .barrier) {
            if let cached = pathHashLookup[hash] {
                return cached
            }

            for entry in index.reversed() {
                if entry.executablePathHash == hash,
                   let message = try? mmapLog.readEvent(at: entry.mmapOffset),
                   let path = message.process.executable?.path {
                    pathHashLookup[hash] = path
                    return path
                }

                if entry.targetPathHash == hash,
                   let message = try? mmapLog.readEvent(at: entry.mmapOffset),
                   let path = message.target_path {
                    pathHashLookup[hash] = path
                    return path
                }
            }

            return nil
        }
    }

    /// Returns MMAP allocation/usage metrics for memory accounting.
    public func getMMapFootprintBytes() -> (allocated: UInt64, used: UInt64) {
        let allocated = UInt64(max(0, mmapLog.currentAllocatedSizeBytes()))
        let used = UInt64(max(0, mmapLog.currentUsedSizeBytes()))
        return (allocated: allocated, used: used)
    }

    // MARK: - Accessors

    /// Returns the event with the given UUID, or `nil`.
    public func getEventByID(_ id: UUID) -> Message? {
        return storeQueue.sync {
            guard let idx = eventIDIndex[id], idx < index.count else { return nil }
            let entry = index[idx]
            return try? mmapLog.readEvent(at: entry.mmapOffset)
        }
    }

    /// Returns the index position for the given UUID, or `nil`.
    public func getIndexForID(_ id: UUID) -> Int? {
        return storeQueue.sync {
            return eventIDIndex[id]
        }
    }

    /// Returns all correlated child events for the given event.
    public func getCorrelatedEvents(for message: Message) -> [Message] {
        return storeQueue.sync {
            guard let idx = eventIDIndex[message.id],
                  let childIndices = correlatedChildren[idx] else { return [] }
            return childIndices
                .compactMap { i in
                    guard i < index.count else { return nil }
                    return try? mmapLog.readEvent(at: index[i].mmapOffset)
                }
                .sorted { $0.mach_time > $1.mach_time }
        }
    }

    /// Returns correlated child indices for the given event index.
    public func getCorrelatedIndices(for index: Int) -> [Int] {
        return storeQueue.sync {
            return correlatedChildren[index] ?? []
        }
    }

    /// Finds the parent process event for a given message.
    ///
    /// Looks for the EXEC or FORK event whose target/child has the same audit token
    /// as this event's initiating process.
    public func findParentProc(message: Message) -> Message? {
        return storeQueue.sync {
            let auditToken = message.process.audit_token_string
            guard let indices = targetAuditTokenIndex[auditToken] else { return nil }
            for idx in indices.reversed() {
                guard idx < index.count, index[idx].id != message.id else { continue }
                if let event = try? mmapLog.readEvent(at: index[idx].mmapOffset) {
                    return event
                }
            }
            return nil
        }
    }

    /// Finds the parent process event index for a given event index.
    public func findParentProcIndex(for idx: Int) -> Int? {
        return storeQueue.sync {
            guard idx < index.count else { return nil }
            let auditToken = index[idx].auditTokenString
            guard let indices = targetAuditTokenIndex[auditToken] else { return nil }
            for i in indices.reversed() {
                if i < index.count && i != idx {
                    return i
                }
            }
            return nil
        }
    }

    /// Constructs a process tree (ancestry chain) for the given event.
    ///
    /// Walks up the parent chain recursively.
    public func getProcTree(for message: Message) -> [Message] {
        var tree: [Message] = []
        var current = message

        while let parent = findParentProc(message: current) {
            tree.append(parent)
            current = parent
        }

        return tree
    }

    /// Returns all EXEC events in the same process group.
    public func getProcGroup(for message: Message) -> [Message] {
        return storeQueue.sync {
            var gid = message.process.group_id
            if let exec = message.event.exec {
                gid = exec.target.group_id
            }
            guard let indices = processGroupIndex[gid] else { return [] }
            return indices
                .compactMap { i in
                    guard i < index.count else { return nil }
                    return try? mmapLog.readEvent(at: index[i].mmapOffset)
                }
                .filter { $0.event.exec != nil }
                .sorted { $0.mach_time > $1.mach_time }
        }
    }

    /// Returns all EXEC events in the same session.
    public func getProcSessionGroup(for message: Message) -> [Message] {
        return storeQueue.sync {
            var sessionID = message.process.session_id
            if let exec = message.event.exec {
                sessionID = exec.target.session_id
            }
            guard let indices = sessionGroupIndex[sessionID] else { return [] }
            return indices
                .compactMap { i in
                    guard i < index.count else { return nil }
                    return try? mmapLog.readEvent(at: index[i].mmapOffset)
                }
                .filter { $0.event.exec != nil }
                .sorted { $0.mach_time > $1.mach_time }
        }
    }

    // MARK: - Async Accessors (for background loading)

    /// Async version of getProcTree - runs on background queue.
    public func getProcTreeAsync(for message: Message) async -> [Message] {
        return await Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return [] }
            var tree: [Message] = []
            var current = message
            while let parent = self.findParentProc(message: current) {
                tree.append(parent)
                current = parent
            }
            return tree
        }.value
    }

    /// Async version of getProcGroup - runs on background queue.
    public func getProcGroupAsync(for message: Message) async -> [Message] {
        return await Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return [] }
            return self.getProcGroup(for: message)
        }.value
    }

    /// Async version of getProcSessionGroup - runs on background queue.
    public func getProcSessionGroupAsync(for message: Message) async -> [Message] {
        return await Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return [] }
            return self.getProcSessionGroup(for: message)
        }.value
    }

    /// Async version of getCorrelatedEvents - runs on background queue.
    public func getCorrelatedEventsAsync(for message: Message) async -> [Message] {
        return await Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return [] }
            return self.getCorrelatedEvents(for: message)
        }.value
    }

    /// Async version of findParentProc - runs on background queue.
    public func findParentProcAsync(message: Message) async -> Message? {
        return await Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return nil }
            return self.findParentProc(message: message)
        }.value
    }

    // MARK: - Telemetry Export

    /// Export all events to a file.
    public func exportFullTrace(jsonl: Bool = false) {
        guard let telemetryFile = showSavePanel() else { return }

        let snapshot = storeQueue.sync { index }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let jsonLines: [String] = snapshot.compactMap { entry in
                guard let message = try? self.mmapLog.readEvent(at: entry.mmapOffset) else { return nil }
                return jsonl
                    ? ProcessHelpers.eventToJSON(value: message)
                    : ProcessHelpers.eventToPrettyJSON(value: message)
            }
            let finalJSON = jsonLines.joined(separator: "\n")

            do {
                try finalJSON.write(to: telemetryFile, atomically: true, encoding: .utf8)
            } catch {
                EventStore.logger.error("Failed to write exported trace: \(error)")
            }
        }
    }

    /// Export selected events to a file.
    public func exportSelectedEvents(eventIDs: [UUID], jsonl: Bool = false) {
        guard let telemetryFile = showSavePanel(numberOfEvents: eventIDs.count) else { return }

        let selectedEvents = eventIDs
            .compactMap { getEventByID($0) }
            .sorted { $0.mach_time < $1.mach_time }

        DispatchQueue.global(qos: .userInitiated).async {
            let jsonStrings = selectedEvents.map { event in
                jsonl
                    ? ProcessHelpers.eventToJSON(value: event)
                    : ProcessHelpers.eventToPrettyJSON(value: event)
            }
            let finalJSON = jsonStrings.joined(separator: "\n")

            guard !finalJSON.isEmpty else { return }
            do {
                try finalJSON.write(to: telemetryFile, atomically: true, encoding: .utf8)
            } catch {
                EventStore.logger.error("Failed to write selected events: \(error)")
            }
        }
    }

    /// Show a save panel for telemetry export.
    public func showSavePanel(numberOfEvents: Int = 0) -> URL? {
        let savePanel = NSSavePanel()
        savePanel.allowedContentTypes = [UTType.json]
        savePanel.canCreateDirectories = true
        savePanel.isExtensionHidden = false
        savePanel.allowsOtherFileTypes = false
        savePanel.title = numberOfEvents == 0 ? "Save full system trace" : "Save \(numberOfEvents) events"
        savePanel.message = "Choose a directory to export the trace to"
        savePanel.nameFieldLabel = "Telemetry file name:"
        let response = savePanel.runModal()
        return response == .OK ? savePanel.url : nil
    }

    // MARK: - Private indexing

    /// Index a single event entry at the given array position.
    private func indexEvent(_ entry: EventIndexEntry, at index: Int) {
        eventIDIndex[entry.id] = index

        if let targetToken = entry.targetAuditTokenString {
            targetAuditTokenIndex[targetToken, default: []].append(index)

            if let gid = entry.targetGroupID {
                processGroupIndex[gid, default: []].append(index)
            }
            if let sid = entry.targetSessionID {
                sessionGroupIndex[sid, default: []].append(index)
            }
        }

        processGroupIndex[entry.groupID, default: []].append(index)
        sessionGroupIndex[entry.sessionID, default: []].append(index)
    }
}
