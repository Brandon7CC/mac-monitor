//
//  EventQueryModel+Preview.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import CoreData
import os
import SutroESFramework


// MARK: - Preview
extension EventQueryModel {
    /// What a predicate matches among every event the tables show from, whatever their filters: how many, and the
    /// first few.
    struct Preview: Equatable {
        /// A matching event, as its row in the Unified table starts.
        struct Example: Identifiable, Equatable {
            let id: NSManagedObjectID
            let time: String
            let type: String
            let context: String
        }

        var matched = 0
        var total = 0
        /// The events it couldn't be checked on.
        var unchecked = 0
        var examples: [Example] = []
    }

    /// Check a predicate on every event, on a context of its own, without changing the tables.
    ///
    /// - Parameters:
    ///   - source: The predicate.
    ///   - audience: What it's for, which decides what it may use.
    ///   - limit: How many matching events to keep as examples.
    /// - Returns: What it matches.
    /// - Throws: The predicate's or the fetch's error, or `CancellationError` once the task is cancelled.
    func preview(_ source: String, for audience: PredicateAudience, examples limit: Int = 5) async throws -> Preview {
        let context = controller.container.newBackgroundContext()
        let cancelled = OSAllocatedUnfairLock(initialState: false)
        return try await withTaskCancellationHandler {
            try await context.perform {
                /// Parsed on the context's queue, which evaluates it.
                let predicate = try StreamFilter.Predicate(source, for: audience)
                var preview = Preview(total: try context.count(for: ESMessage.request()))
                let byTime = [NSSortDescriptor(key: "mach_time", ascending: true)]
                try Worker(context: context).forEachEvent(matching: predicate.storePredicate, sortedBy: byTime,
                                                          isCurrent: { !cancelled.withLock { $0 } }) { message in
                    let matches: Bool
                    do {
                        matches = try predicate.evaluate(on: message)
                    } catch {
                        preview.unchecked += 1
                        return
                    }
                    guard matches else { return }
                    preview.matched += 1
                    if preview.examples.count < limit {
                        preview.examples.append(Preview.Example(
                            id: message.objectID, time: eventTimeStamp(for: message),
                            type: message.es_event_type ?? "", context: message.context ?? ""))
                    }
                }
                return preview
            }
        } onCancel: {
            cancelled.withLock { $0 = true }
        }
    }
}
