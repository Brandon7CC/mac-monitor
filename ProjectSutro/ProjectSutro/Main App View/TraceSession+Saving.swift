//
//  TraceSession+Saving.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import AppKit
import SutroESFramework


// MARK: - Saving
extension TraceSession {
    /// A save in progress, or one that failed until its sheet's OK.
    struct Saving: Identifiable {
        /// The file being written. It changes only once every event is written.
        let url: URL
        /// Was there a file there already, which a save that doesn't finish leaves as it was?
        let replacing: Bool
        /// The export, to cancel.
        let exporter: TelemetryExporter
        /// The main window whose sheet shows it. It's `nil` until a main window opens.
        var window: UUID?
        /// How far it has got, once it knows its events.
        var progress: TelemetryExporter.Progress?
        /// Was Cancel clicked? The export stops at its next batch.
        var isCancelled = false
        /// Why the file wasn't saved, once the save failed.
        var failure: String?

        /// One save's identity, the same while its progress changes.
        var id: ObjectIdentifier { ObjectIdentifier(exporter) }
    }

    /// Export telemetry: choose a file and save the full trace or the selected events to it in the background, unless a
    /// save is already going. The sheet belongs to the main window that was key last.
    ///
    /// - Parameters:
    ///   - eventIDs: The selected events, or `nil` for the full trace.
    ///   - jsonl: JSON Lines (`true`) or pretty-printed JSON (`false`).
    ///   - showWindow: Opens a main window for the sheet. It's called only when none is open.
    func save(eventIDs: [UUID]? = nil, jsonl: Bool, showWindow: () -> Void = {}) {
        guard saving == nil,
              let url = store.showSavePanel(numberOfEvents: eventIDs?.count ?? 0, jsonl: jsonl) else { return }
        /// Reports from a save that has since finished are ignored.
        var exporter: TelemetryExporter?
        let progress = { [weak self] (state: TelemetryExporter.Progress) in
            guard let self, self.saving?.exporter === exporter else { return }
            self.saving?.progress = state
        }
        let completion = { [weak self] (result: Swift.Result<Int, Error>) in
            guard let self, let saving = self.saving, saving.exporter === exporter else { return }
            self.saved(saving, result)
        }
        /// Checked first: a short save can rename over the file before the next line runs.
        let replacing = FileManager.default.fileExists(atPath: url.path)
        let started = store.exportEvents(eventIDs, to: url, jsonl: jsonl, progress: progress, completion: completion)
        exporter = started
        saving = Saving(url: url, replacing: replacing, exporter: started, window: windows.first)
        showsSaving = false
        if windows.isEmpty { showWindow() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
            guard let self, self.saving?.exporter === started else { return }
            self.showsSaving = true
        }
    }

    /// Cancel: stop saving and leave the file as it was.
    func stopSaving() {
        saving?.isCancelled = true
        saving?.exporter.cancel()
    }

    /// OK on a failed save's sheet.
    func closeSaveFailure() {
        guard saving?.failure != nil else { return }
        (saving, showsSaving) = (nil, false)
    }

    /// The save a main window's sheet shows.
    ///
    /// - Parameter window: The main window.
    /// - Returns: The save, once it has run half a second or failed, when it belongs to the window. Otherwise `nil`.
    func save(shownIn window: UUID) -> Saving? {
        guard let saving, saving.window == window, showsSaving || saving.failure != nil else { return nil }
        return saving
    }

    /// A save ended. Success or Cancel closes its sheet. A failure shows why in the sheet, or in an alert with no main
    /// window. One long enough to show asks for attention if Mac Monitor is in the background.
    ///
    /// - Parameters:
    ///   - saving: The save.
    ///   - result: The number of events written, or why the file wasn't.
    private func saved(_ saving: Saving, _ result: Swift.Result<Int, Error>) {
        let shown = showsSaving
        switch result {
        case .failure(let error) where !(error is CancellationError):
            let failure = error.localizedDescription
                + (saving.replacing ? " The file is as it was." : " Nothing was saved.")
            if saving.window == nil {
                (self.saving, showsSaving) = (nil, false)
                Self.show("Mac Monitor couldn't save “\(saving.url.lastPathComponent)”.", failure)
            } else {
                self.saving?.failure = failure
            }
        case .success where shown && !NSApp.isActive:
            (self.saving, showsSaving) = (nil, false)
            NSApp.requestUserAttention(.informationalRequest)
        case .success, .failure:
            (self.saving, showsSaving) = (nil, false)
        }
    }

    // MARK: Windows
    /// A main window opened. A save no window shows yet is shown in it.
    ///
    /// - Parameters:
    ///   - window: The window's identity.
    ///   - isKey: Is it the key window?
    func windowAppeared(_ window: UUID, isKey: Bool) {
        windows.removeAll { $0 == window }
        windows.insert(window, at: isKey ? 0 : windows.endIndex)
        if saving != nil && saving?.window == nil { saving?.window = window }
    }

    /// A main window became key, so the next save's sheet belongs to it.
    ///
    /// - Parameter window: The window's identity.
    func windowBecameKey(_ window: UUID) {
        windows.removeAll { $0 == window }
        windows.insert(window, at: 0)
    }

    /// A main window closed. The main window key last takes over its save's sheet.
    ///
    /// - Parameter window: The window's identity.
    func windowDisappeared(_ window: UUID) {
        windows.removeAll { $0 == window }
        if saving?.window == window { saving?.window = windows.first }
    }
}
