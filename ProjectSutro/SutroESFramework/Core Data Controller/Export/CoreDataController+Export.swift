//
//  CoreDataController+Export.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import AppKit
import CoreData
import OSLog
import UniformTypeIdentifiers
import os


extension CoreDataController {
    // MARK: - Telemetry export
    
    /// Export system events to a file: the full trace, or the selected events.
    ///
    /// We can export the events to either JSON or JSONL format: the full trace of a live recording sorted by
    /// `mach_time`, of an opened trace in its file order, and a selection sorted by `mach_time`. The export starts once
    /// the inserts already queued have been saved, and covers the events saved up to then: what it covered when it ran
    /// on `privateMOC`, without holding that queue while exporting. The events are streamed to the file in the
    /// background (see ``TelemetryExporter``), so recording carries on meanwhile.
    ///
    /// - Parameters:
    ///   - eventIDs: The `UUID`s of the selected events, or `nil` for the full trace. The full trace is written even
    ///     when it's empty, a selection only when the store has some of its events.
    ///   - url: The destination, from ``showSavePanel(numberOfEvents:jsonl:)``.
    ///   - jsonl: Should we export the events line-by-line (one JSON object per line)?
    ///   - progress: Called on the main thread with how far the export has got, once it knows its events.
    ///   - completion: Called on the main thread with the number of events written, or why none were
    ///     (`CancellationError` after ``TelemetryExporter/cancel()``).
    /// - Returns: The export, to cancel.
    @discardableResult
    public func exportEvents(_ eventIDs: [UUID]? = nil, to url: URL, jsonl: Bool = false,
                             progress: @escaping (TelemetryExporter.Progress) -> Void = { _ in },
                             completion: @escaping (Result<Int, Error>) -> Void = { _ in }) -> TelemetryExporter {
        let exporter = TelemetryExporter(container: container, pretty: !jsonl), source = self.source
        let key = ObjectIdentifier(exporter)
        exports.withLock { $0[key] = (exporter, url) }
        privateMOC.perform {
            /// Saves and Clears queued after this block come after the snapshot.
            let batch = self.lastInsertBatch
            exporter.pin()
            exporter.run(to: url, writeIfEmpty: eventIDs == nil, choose: {
                try eventIDs.map($0.events(withIDs:)) ?? $0.allEvents(through: batch, from: source)
            }, progress: { state in
                DispatchQueue.main.async { progress(state) }
            }) { result in
                self.exports.withLock { $0[key] = nil }
                if case .failure(let error) = result, !(error is CancellationError) {
                    CoreDataController.logger.error(
                        "Failed to export telemetry: \(error.localizedDescription, privacy: .public)")
                }
                DispatchQueue.main.async { completion(result) }
            }
        }
        return exporter
    }
    
    /// The files exports in progress are writing, so quitting can say what it would stop. Any thread.
    public var exportDestinations: [URL] { exports.withLock { $0.values.map(\.url) } }
    
    /// AppKit UI to save system traces.
    ///
    /// Show the `NSSavePanel`. A JSONL export is named `.jsonl` (JSON Lines, which the app declares), pretty JSON
    /// `.json`.
    ///
    /// - Parameters:
    ///   - numberOfEvents: The number of events to save (to be displayed in the UI)
    ///   - jsonl: Is the export JSONL (one JSON object per line)?
    ///
    ///  - Returns: `URL?`:  The optional URL to save the telemetry to
    ///
    public func showSavePanel(numberOfEvents: Int = 0, jsonl: Bool = false) -> URL? {
        let savePanel = NSSavePanel()
        savePanel.allowedContentTypes = [jsonl ? (UTType(filenameExtension: "jsonl") ?? .json) : .json]
        savePanel.canCreateDirectories = true
        savePanel.isExtensionHidden = false
        savePanel.allowsOtherFileTypes = false
        savePanel.title = numberOfEvents == 0 ? "Save full system trace" : "Save \(numberOfEvents) events"
        savePanel.message = "Choose a directory to export the trace to"
        savePanel.nameFieldLabel = "Telemetry file name:"
        let response = savePanel.runModal()
        return response == .OK ? savePanel.url : nil
    }
}
