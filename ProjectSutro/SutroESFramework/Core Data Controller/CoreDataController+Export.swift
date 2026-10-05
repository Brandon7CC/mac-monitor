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
    
    /// Export all system events to a file
    ///
    /// We can export all system events from the event store to either JSON or JSONL format: a live recording's sorted
    /// by `mach_time`, an opened trace's in its file order. The events are streamed to the file in the background (see
    /// ``TelemetryExporter``), so recording carries on meanwhile.
    ///
    /// - Parameters:
    ///   - jsonl: Should we export the events line-by-line (one JSON object per line)?
    ///
    public func exportFullTrace(jsonl: Bool = false) {
        // UI work must be on the main thread.
        guard let telemetryFile = showSavePanel(jsonl: jsonl) else { return }
        let source = self.source
        export(to: telemetryFile, jsonl: jsonl, writeIfEmpty: true) { exporter, batch in
            try exporter.allEvents(through: batch, from: source)
        }
    }
    
    /// Export specified system events to a file, sorted by `mach_time`.
    ///
    /// The events are looked up and streamed to the file in the background (see ``TelemetryExporter``).
    ///
    /// - Parameters:
    ///   - eventIDs: A listing of the event `UUID`s we want to export.
    ///   - jsonl: Should we export the events line-by-line (one JSON object per line)?
    ///
    public func exportSelectedEvents(eventIDs: [UUID], jsonl: Bool = false) {
        // UI work must be on the main thread.
        guard let telemetryFile = showSavePanel(numberOfEvents: eventIDs.count, jsonl: jsonl) else { return }
        export(to: telemetryFile, jsonl: jsonl, writeIfEmpty: false) { exporter, _ in try exporter.events(withIDs: eventIDs) }
    }


    
    /// Stream events to `url` in the background.
    ///
    /// The export starts once the inserts already queued have been saved, and covers the events saved up to then (the
    /// batch passed to `choose`): what it covered when it ran on `privateMOC`, without holding that queue while exporting.
    ///
    /// - Parameters:
    ///   - url: The destination, from the save panel.
    ///   - jsonl: JSONL (`true`) or pretty JSON (`false`).
    ///   - writeIfEmpty: Write an empty file when no events are chosen.
    ///   - choose: Picks the events, in file order, given the last ``ESMessage/insert_batch`` to cover.
    private func export(to url: URL, jsonl: Bool, writeIfEmpty: Bool,
                        choose: @escaping (TelemetryExporter, Int64) throws -> [NSManagedObjectID]) {
        let exporter = TelemetryExporter(container: container, pretty: !jsonl)
        let key = ObjectIdentifier(exporter)
        exports.withLock { $0[key] = exporter }
        privateMOC.perform {
            /// Saves and Clears queued after this block come after the snapshot.
            let batch = self.lastInsertBatch
            exporter.pin()
            exporter.run(to: url, writeIfEmpty: writeIfEmpty, choose: { try choose($0, batch) }) { result in
                self.exports.withLock { $0[key] = nil }
                if case .failure(let error) = result, !(error is CancellationError) {
                    CoreDataController.logger.error("Failed to export telemetry: \(error.localizedDescription, privacy: .public)")
                }
            }
        }
    }
    
    /// AppKit UI to save system traces.
    ///
    /// Show the `NSSavePanel`. A JSONL export is named `.jsonl` (JSON Lines, which the app declares), pretty JSON `.json`.
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
