//
//  EventFilterSpec.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/1/26.
//

import Foundation
import CoreData
import EndpointSecurity
import SutroESFramework


// MARK: - Filter spec
/// Everything that decides which events the event tables show, as a value.
///
/// The event tables turn this into an `NSPredicate` and let Core Data do the filtering instead of loading every event.
/// Each clause below reproduces the in-memory filter it replaced (`isEventFiltered`, v2.1) exactly, including how `nil`
/// values compare.
struct EventFilterSpec: Equatable {
    var filters: Filters
    var searchText: String
    var filteringLongRunningProcs: Bool
    var clientConnectDT: Date
    
    /// `ES_EVENT_TYPE_NOTIFY_EXEC` / `ES_EVENT_TYPE_NOTIFY_FORK`, as stored in `ESMessage.event_type`.
    static let execEventType = ESMessage.execEventType
    static let forkEventType = ESMessage.forkEventType
    
    /// The paths of the selected process trees ("→ Only" / "↕ Full tree").
    var inclusionRoots: [String] {
        [filters.rootIncludedInitiatingProcessPath, filters.rootIncludedTargetProcessPath].compactMap { $0 }
    }
    
    /// "↕ Full tree" needs the process lineage, which can't be expressed as a predicate (see ``ProcessLineageIndex``).
    var needsLineage: Bool { filters.shouldIncludeProcessSubTrees && !inclusionRoots.isEmpty }
    
    /// Build the predicate for the events that pass every filter.
    ///
    /// - Parameter lineage: The audit tokens in the selected process trees. Required when ``needsLineage``.
    /// - Returns: A predicate on `ESMessage` using only its own (denormalized) attributes.
    func predicate(lineage: Set<String>?) -> NSPredicate {
        var clauses: [NSPredicate] = []
        
        // Inclusion: the initiating process, or an exec's target, is in a selected tree (or has a selected path).
        if !inclusionRoots.isEmpty {
            if filters.shouldIncludeProcessSubTrees {
                let tokens = Array(lineage ?? [])
                clauses.append(NSPredicate(format: "instigator_audit_token IN %@ OR (event_type == %d AND created_audit_token IN %@)", tokens, Self.execEventType, tokens))
            } else {
                clauses.append(NSPredicate(format: "initiating_path IN %@ OR (event_type == %d AND created_path IN %@)", inclusionRoots, Self.execEventType, inclusionRoots))
            }
        }
        
        if filteringLongRunningProcs {
            clauses.append(NSPredicate(format: "message_darwin_time == nil OR message_darwin_time >= %@", clientConnectDT as NSDate))
        }
        
        clauses.append(contentsOf: [
            Self.excluding("es_event_type", filters.events),
            Self.excluding("initiating_euid_human", filters.userIDs),
            Self.excluding("initiating_path", filters.initiatingPaths),
        ].compactMap { $0 })
        
        // Target paths hide exact matches (a `nil` target counts as "") and any target containing a non-empty entry.
        if filters.targetPaths.contains("") {
            clauses.append(NSPredicate(format: "target_path != nil AND target_path != ''"))
        }
        let contained = Set(filters.targetPaths.filter { !$0.isEmpty })
        if !contained.isEmpty {
            let any = NSCompoundPredicate(orPredicateWithSubpredicates: contained.map { NSPredicate(format: "target_path CONTAINS %@", $0) })
            clauses.append(NSCompoundPredicate(orPredicateWithSubpredicates: [NSPredicate(format: "target_path == nil"), NSCompoundPredicate(notPredicateWithSubpredicate: any)]))
        }
        
        if !searchText.isEmpty {
            clauses.append(NSPredicate(format: "context == nil OR context CONTAINS[c] %@", searchText))
        }
        
        return clauses.isEmpty ? NSPredicate(value: true) : NSCompoundPredicate(andPredicateWithSubpredicates: clauses)
    }
    
    /// Keep events whose `key` isn't one of `values`, reading `nil` as `""` like `!values.contains(value ?? "")` does.
    ///
    /// SQL compares `NULL` to nothing, so `nil` is handled explicitly.
    ///
    /// - Parameters:
    ///   - key: An `ESMessage` string attribute.
    ///   - values: The values to hide.
    /// - Returns: The clause, or `nil` when there's nothing to hide.
    private static func excluding(_ key: String, _ values: [String]) -> NSPredicate? {
        guard !values.isEmpty else { return nil }
        let hidden = Array(Set(values))
        return hidden.contains("")
            ? NSPredicate(format: "%K != nil AND NOT (%K IN %@)", key, key, hidden)
            : NSPredicate(format: "%K == nil OR NOT (%K IN %@)", key, key, hidden)
    }
}


// MARK: - Process lineage
/// Process trees built from the denormalized lineage columns, matching the resolver they replaced (`ProcessLineageResolver`,
/// v2.1) exactly.
///
/// That resolver walked every `ESMessage` and its relationships. This builds the same graph from a dictionary
/// fetch of a few columns (``fetchRequest(_:)``), so "↕ Full tree" works without loading every event, and it can be kept
/// up to date one batch of new events at a time.
struct ProcessLineageIndex {
    private struct Node: Equatable { let parent: String; let path: String }
    private var nodes: [String: Node] = [:]
    private var children: [String: Set<String>] = [:]
    /// Every audit token any added event mentioned, with or without a path.
    private var seen: Set<String> = []
    
    /// A request for the lineage columns of the events matching `predicate`, newest first, ready for ``add(_:)``.
    ///
    /// - Parameter predicate: The events to read.
    /// - Returns: A dictionary fetch request on `ESMessage`.
    static func fetchRequest(_ predicate: NSPredicate) -> NSFetchRequest<NSDictionary> {
        let request = NSFetchRequest<NSDictionary>(entityName: "ESMessage")
        request.resultType = .dictionaryResultType
        request.predicate = predicate
        request.propertiesToFetch = ["instigator_audit_token", "instigator_parent_audit_token", "initiating_path", "initiating_pid",
                                     "event_type", "created_audit_token", "created_path", "created_pid"]
        request.sortDescriptors = [NSSortDescriptor(key: "mach_time", ascending: false)]
        return request
    }
    
    /// Add events newer than everything added so far.
    ///
    /// Like the resolver (fed newest first), the newest sighting of a process decides its parent and path, and sightings
    /// without a path are ignored. So within `rows` the first sighting wins, and it replaces what older rows said.
    ///
    /// - Parameter rows: Rows from ``fetchRequest(_:)``, newest first.
    /// - Returns: The audit tokens no earlier event mentioned.
    @discardableResult
    mutating func add(_ rows: [NSDictionary]) -> Set<String> {
        var claimed = Set<String>()
        var fresh = Set<String>()
        func sighting(_ token: String, parent: String, path: String?) {
            if seen.insert(token).inserted { fresh.insert(token) }
            guard let path, claimed.insert(token).inserted else { return }
            let node = Node(parent: parent, path: path)
            if let old = nodes[token] {
                guard old != node else { return }
                children[old.parent]?.remove(token)
            }
            nodes[token] = node
            children[parent, default: []].insert(token)
        }
        
        for row in rows {
            guard let token = row["instigator_audit_token"] as? String else { continue }
            let parent = row["instigator_parent_audit_token"] as? String ?? ""
            sighting(token, parent: parent, path: row["initiating_path"] as? String)
            
            guard let created = row["created_audit_token"] as? String else { continue }
            switch (row["event_type"] as? NSNumber)?.int32Value {
            case EventFilterSpec.execEventType:
                /// An exec that keeps its pid replaces the process, so it hangs off the instigator's parent.
                let samePid = (row["created_pid"] as? NSNumber)?.int32Value == (row["initiating_pid"] as? NSNumber)?.int32Value
                sighting(created, parent: samePid ? parent : token, path: row["created_path"] as? String)
            case EventFilterSpec.forkEventType:
                sighting(created, parent: token, path: row["created_path"] as? String)
            default:
                break
            }
        }
        return fresh
    }
    
    /// The tokens in the tree of every process with `path`: each match, its ancestors, and its descendants.
    ///
    /// Mirrors `ProcessLineageResolver.computeLineageSet(includedPath:includeAncestors:)` (v2.1) with ancestors included.
    /// Each root gets its own set (as Mac Monitor does for the initiating and target roots) because a shared set would
    /// stop walking descendants at processes another root already added.
    ///
    /// - Parameter path: The selected executable path.
    /// - Returns: The audit tokens in that path's lineage.
    func lineage(of path: String) -> Set<String> {
        var result = Set<String>()
        for (token, node) in nodes where node.path == path {
            result.insert(token)
            var current = token
            var visited = Set<String>()
            while let ancestor = nodes[current], !visited.contains(current) {
                result.insert(current)
                visited.insert(current)
                current = ancestor.parent
            }
            var stack = [token]
            while let next = stack.popLast() {
                for child in children[next] ?? [] where result.insert(child).inserted {
                    stack.append(child)
                }
            }
        }
        return result
    }
}


// MARK: - Chart labels
/// The mini-chart's label for each `es_event_type`. Matches `SystemChartEventView`, which also sets the bars' order.
enum EventChartLabels {
    private static let prefix = "ES_EVENT_TYPE_NOTIFY_"
    private static let renamed: [String: String] = [
        "BTM_LAUNCH_ITEM_ADD": "LAUNCH_ITEM_ADD",
        "BTM_LAUNCH_ITEM_REMOVE": "LAUNCH_ITEM_REMOVE",
        "LW_SESSION_UNLOCK": "LW_UNLOCK",
        "LW_SESSION_LOGIN": "LW_LOGIN",
        "REMOTE_THREAD_CREATE": "REMOTE_THREAD",
        "AUTHORIZATION_PETITION": "AUTH_PETITION",
        "AUTHORIZATION_JUDGEMENT": "AUTH_JUDGEMENT",
        "OD_CREATE_GROUP": "OD_GROUP_CREATE",
        "OD_ATTRIBUTE_VALUE_ADD": "OD_ATTR_ADD",
    ]
    
    /// - Parameter eventType: An `ES_EVENT_TYPE_NOTIFY_*` name.
    /// - Returns: The chart label (e.g. `EXEC`, `LW_UNLOCK`).
    static func label(for eventType: String) -> String {
        let name = eventType.hasPrefix(prefix) ? String(eventType.dropFirst(prefix.count)) : eventType
        return renamed[name] ?? name
    }
}
