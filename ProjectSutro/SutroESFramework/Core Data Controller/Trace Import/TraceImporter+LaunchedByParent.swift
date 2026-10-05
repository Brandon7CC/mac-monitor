//
//  TraceImporter+LaunchedByParent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - A trace's launched-by parents
/// Names the launched-by parent of each process a trace's execs and forks create, when the trace doesn't carry one:
/// eslogger's traces, Mac Monitor 2.1's exports, 2.2's from before the launched-by parent, and events an older Security
/// Extension sent.
///
/// Each is resolved from the trace's own fields (``LaunchedByParent/ResolvedBy/import``), the way the Security
/// Extension resolves them. A parent's path is only named from the processes the trace showed before it, matched by pid
/// and pid version: nothing is read from this Mac, which may not be the one the trace was recorded on. A launched-by
/// parent the trace carries (Mac Monitor 2.2's, whose LaunchServices answer can't be worked out again) is kept.
///
/// ``TraceImporter`` decodes each batch in parallel, then fills it here in file order, so a parent seen in an earlier
/// batch is still named. The memory is bounded (``ProcessPathMemory/traceCapacity``): a parent first seen very early in
/// a huge trace may lose its path, never its token.
///
/// Only used on the importer's queue.
final class TraceLaunchedByParents {
    /// The executables of the processes the trace has named so far.
    private let paths: ProcessPathMemory
    
    /// - Parameter capacity: The processes each generation of the memory holds.
    init(capacity: Int = ProcessPathMemory.traceCapacity) {
        paths = ProcessPathMemory(capacity: capacity)
    }
    
    /// Name the launched-by parent of each exec's and fork's created process that has none, remembering every process
    /// the events name as it goes.
    ///
    /// - Parameter messages: A batch of the trace's events, in file order, after every batch before it.
    func fill(_ messages: inout [Message]) {
        /// Through the array's storage, so reading an event's fields never copies the event.
        messages.withUnsafeMutableBufferPointer { events in
            for index in events.indices {
                paths.remember(events[index].process)
                /// By `event_type`, rather than a switch on `event`, which copies it: most events create no process.
                guard Self.creatingTypes.contains(events[index].event_type) else { continue }
                events[index].resolveLaunchedByParent(by: .import) { _, token in paths.path(of: token) }
                paths.remember(processesOf: events[index])
            }
        }
    }
    
    /// The `event_type`s of exec and fork, the events that create a process.
    private static let creatingTypes = Set([ESMessage.execEventType, ESMessage.forkEventType].map(Int.init))
}
