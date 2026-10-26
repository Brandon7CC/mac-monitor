//
//  RecordKeyLibrary.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation
import SutroESFramework


// MARK: - Keys
/// The record's key paths, from the telemetry schema Mac Monitor ships, grouped for the predicate editor: the related
/// events a SUBQUERY goes through, the record's own keys, the process's, and each event type's.
enum RecordKeyLibrary {
    struct Key: Identifiable, Hashable {
        let path: String
        /// Its JSON type: string, integer, boolean, array or object, or "related" for related events.
        let type: String
        /// What it is, under its path.
        var detail: String?
        /// What the schema says of it, as its help.
        var summary: String?
        /// What clicking it inserts, when not its path.
        var insertion: String?
        var id: String { path }
    }

    /// The related events' group's title.
    static let relatedTitle = "Related events"

    /// Each relation, inserting a SUBQUERY of it to edit.
    static let related = Group(title: relatedTitle, keys: PredicateRelation.allCases.map { relation in
        let conditions: String
        switch relation {
        case .events:
            conditions = #"$e.es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" "#
                + "AND $e.event.exec.target.executable.path == target_path"
        case .processGroup: conditions = #"$e.es_event_type == "ES_EVENT_TYPE_NOTIFY_CREATE""#
        case .sessionGroup: conditions = #"$e.es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#
        case .correlated: conditions = #"$e.target_path CONTAINS "NSCreateObjectFileImageFromMemory""#
        case .processEvents: conditions = #"$e.es_event_type == "ES_EVENT_TYPE_NOTIFY_OPEN""#
        }
        return Key(path: relation.rawValue, type: "related", detail: relation.summary,
                   insertion: "SUBQUERY(\(relation.rawValue), $e, \(conditions)).@count > 0")
    })

    struct Group: Identifiable {
        let title: String
        let keys: [Key]
        var id: String { title }
    }

    /// Related events, Record, Process, then each event type by name. An array's objects' keys aren't listed: the
    /// array is.
    static let groups: [Group] = {
        let keys = RecordKeyPaths.shared.nodes.compactMap { path, node -> Key? in
            path.isEmpty || node.type == "object" || node.isInArray
                ? nil : Key(path: path, type: node.type, summary: node.summary)
        }
        .sorted { $0.path < $1.path }

        var grouped: [String: [Key]] = [:]
        for key in keys {
            let parts = key.path.split(separator: ".")
            let title = parts.first == "process" ? "Process" : parts.first == "event" && parts.count > 1
                ? String(parts[1]) : "Record"
            grouped[title, default: []].append(key)
        }
        let order = ["Record", "Process", "exec"]
        let schemaGroups = grouped.sorted { a, b in
            let (i, j) = (order.firstIndex(of: a.key) ?? order.count, order.firstIndex(of: b.key) ?? order.count)
            return i != j ? i < j : a.key < b.key
        }
        .map { Group(title: $0.key, keys: $0.value) }
        return [related] + schemaGroups
    }()
}
