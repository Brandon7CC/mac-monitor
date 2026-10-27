//
//  TraceSessionViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Toolbar
/// The toolbar's trace status: while reading, the progress (by bytes) and Cancel; afterwards, what was skipped.
///
/// Also shows "Clearing previous events…" while a Clear that takes a while (many events) is deleting, and a save's
/// progress and Cancel while one that takes a while is writing.
struct TraceStatusView: View {
    /// The session whose trace this shows.
    @ObservedObject var session: TraceSession
    
    /// A save's progress, then the trace's: each its own toolbar item, and none while there's nothing to show.
    var body: some View {
        if session.showsSaving, let saving = session.saving {
            TraceSaveStatus(name: saving.url.lastPathComponent, replacing: saving.replacing, progress: saving.progress,
                            cancel: session.stopSaving)
        }
        trace
    }
    
    /// Progress and Cancel while reading, clearing while a Clear deletes, or what was skipped.
    @ViewBuilder private var trace: some View {
        if session.isOpening {
            HStack(spacing: 6) {
                if session.isClearing {
                    clearing
                } else {
                    let fraction = session.progress?.fraction ?? 0
                    ProgressView(value: fraction)
                        .frame(width: 120)
                        .help(session.subtitle)
                    Text(TraceSession.percent(fraction))
                        .monospacedDigit()
                }
                Button("Cancel") { session.stop() }
                    .help("Stop reading and keep the events read so far")
            }
        } else if session.isClearing {
            clearing
        } else if let summary = session.summary, let problems = Self.problems(summary) {
            Label(problems.text, systemImage: "exclamationmark.triangle.fill")
                .labelStyle(.titleAndIcon)
                .symbolRenderingMode(.multicolor)
                .help(problems.details)
        }
    }
    
    /// A spinner and "Clearing previous events…".
    private var clearing: some View {
        HStack(spacing: 6) {
            ProgressView()
                .controlSize(.small)
            Text("Clearing previous events…")
                .foregroundColor(.secondary)
        }
    }
    
    /// What a trace held that isn't showing.
    ///
    /// - Parameter summary: How reading the trace ended.
    /// - Returns: A short note ("7 skipped, 2 unsupported") and its details, or `nil` if every record was shown.
    private static func problems(_ summary: TraceImporter.Summary) -> (text: String, details: String)? {
        let unsupported = summary.unsupportedCount
        var text: [String] = [], details: [String] = []
        if summary.skipped > 0 {
            text.append("\(summary.skipped.formatted()) skipped")
            let skipped = summary.skipped == 1 ? "1 record wasn't an event and was skipped. It's"
                : "\(summary.skipped.formatted()) records weren't events and were skipped. The first is"
            details.append("\(skipped) on line \((summary.firstSkippedLine ?? 1).formatted()).")
        }
        if unsupported > 0 {
            text.append("\(unsupported.formatted()) unsupported")
            var types = summary.unsupported.sorted { $0.key < $1.key }.map { "\($0.key) (\($0.value.formatted()))" }
            if summary.unsupportedOther > 0 { types.append("other types (\(summary.unsupportedOther.formatted()))") }
            details.append("Event types Mac Monitor doesn't show: \(types.joined(separator: ", ")).")
        }
        return text.isEmpty ? nil : (text.joined(separator: ", "), details.joined(separator: "\n"))
    }
}


/// A save that's taking a while: its progress (by events) and Cancel, or a spinner until it knows its events.
struct TraceSaveStatus: View {
    /// The file being written.
    let name: String
    /// Is it replacing a file that's already there?
    let replacing: Bool
    /// How far the save has got, `nil` until it knows its events.
    let progress: TelemetryExporter.Progress?
    /// Stops the save, leaving the file as it was.
    let cancel: () -> Void
    
    /// The progress bar or spinner, "Saving", and Cancel.
    var body: some View {
        HStack(spacing: 6) {
            if let progress {
                ProgressView(value: progress.fraction)
                    .frame(width: 120)
                Text("Saving \(TraceSession.percent(progress.fraction))")
                    .monospacedDigit()
            } else {
                ProgressView()
                    .controlSize(.small)
                Text("Saving…")
                    .foregroundColor(.secondary)
            }
            Button("Cancel", action: cancel)
                .help(replacing
                      ? "Stop saving and leave “\(name)” as it was"
                      : "Stop saving without creating “\(name)”")
        }
        .help(progress.map {
            "Saving \($0.written.formatted()) of \(TraceSession.counted($0.total, "event")) to “\(name)”"
        } ?? "Saving “\(name)”")
    }
}


// MARK: - Window
/// Gives the window the trace's proxy icon (and path menu) while one is open.
///
/// Meant for a window's background: `navigationDocument(_:)` can't be turned off, and adding or removing it on the
/// window's content would rebuild that content (running its `onAppear` again) whenever a trace opens or closes.
struct TraceDocument: View {
    /// The open trace, `nil` while live.
    let url: URL?
    
    /// Nothing to see: an empty view naming the trace as the window's document.
    var body: some View {
        if let url { Color.clear.navigationDocument(url) }
    }
}
