//
//  CoreDataController+OpenTrace.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation

extension CoreDataController {
    // MARK: - Open Trace
    
    /// Replace the store's events with a trace file's, read in the background (see ``TraceImporter``), like opening a
    /// saved Process Monitor log (#38).
    ///
    /// Clears the store first (``eventsWillClear`` and ``eventsDidClear``). Then the trace's events arrive the way a
    /// recording's do (``eventsInserted``), so the tables fill in as the file is read. Recorded events are dropped until
    /// the next ``clearSystemEvents(source:)`` closes the trace. Call on the main thread, once
    /// ``TraceImporter/preflight(_:)`` has accepted the file.
    ///
    /// - Parameters:
    ///   - url: The trace.
    ///   - progress: Called on the main thread, at most ten times a second.
    ///   - completion: Called on the main thread once, when the file has been read, or reading stopped or failed.
    /// - Returns: The import, to stop it.
    @discardableResult
    public func openTrace(at url: URL, progress: @escaping (TraceImporter.Progress) -> Void = { _ in },
                          completion: @escaping (TraceImporter.Summary) -> Void) -> TraceImporter {
        let importer = TraceImporter(url: url, store: self, clear: clearSystemEvents(source: .trace(url)))
        currentImport = importer
        importer.run(progress: progress, completion: completion)
        return importer
    }
}
