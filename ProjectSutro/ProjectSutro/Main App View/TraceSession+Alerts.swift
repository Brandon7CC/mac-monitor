//
//  TraceSession+Alerts.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import AppKit
import SutroESFramework


// MARK: - Alerts
extension TraceSession {
    /// Ask before a trace replaces recorded events, unless the user turned the warning off. A trace replacing a trace,
    /// or a recording that hasn't recorded anything yet, loses nothing and never asks.
    ///
    /// - Parameters:
    ///   - url: The trace.
    ///   - recording: Is Mac Monitor recording?
    /// - Returns: Whether to go ahead.
    func confirmReplacingRecordedEvents(with url: URL, recording: Bool) -> Bool {
        guard isLive, UserDefaults.standard.bool(forKey: "lifecycleWarnBeforeClear") else { return true }
        let events = store.eventCount
        guard events > 0 else { return true }
        let alert = NSAlert()
        alert.messageText = "Replace \(Self.counted(events, "recorded event"))?"
        alert.informativeText = "Opening “\(url.lastPathComponent)” removes the recorded events"
            + (recording ? " and stops recording" : "") + ". Export them first to keep them."
        alert.addButton(withTitle: "Open")
        alert.addButton(withTitle: "Cancel")
        alert.showsSuppressionButton = true
        let response = alert.runModal()
        if alert.suppressionButton?.state == .on {
            UserDefaults.standard.set(false, forKey: "lifecycleWarnBeforeClear")
        }
        return response == .alertFirstButtonReturn
    }
    
    /// The file can't be opened. Nothing has been cleared.
    ///
    /// - Parameters:
    ///   - url: The file.
    ///   - error: Why.
    static func alert(cantOpen url: URL, _ error: Error) {
        let name = url.lastPathComponent
        switch error {
        case TraceImporter.Failure.empty:
            show("“\(name)” is empty.", "There are no events to show.")
        case TraceImporter.Failure.notATrace:
            show("“\(name)” isn't a trace.", "Mac Monitor opens eslogger's JSON and Mac Monitor's JSON exports.")
        default:
            show("Mac Monitor can't open “\(name)”.", error.localizedDescription)
        }
    }
    
    /// Reading stopped partway. The events read so far are showing.
    ///
    /// - Parameters:
    ///   - summary: What was read.
    ///   - error: Why reading stopped.
    static func alert(stoppedReading summary: TraceImporter.Summary, _ error: Error) {
        let first = summary.saved == 1 ? "event is" : "\(summary.saved.formatted()) events are"
        show("Mac Monitor stopped reading “\(summary.url.lastPathComponent)”.",
             "\(error.localizedDescription) The first \(first) shown.")
    }
    
    /// Show a warning.
    ///
    /// - Parameters:
    ///   - message: The alert's title.
    ///   - information: The alert's text.
    static func show(_ message: String, _ information: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = message
        alert.informativeText = information
        alert.runModal()
    }
}
