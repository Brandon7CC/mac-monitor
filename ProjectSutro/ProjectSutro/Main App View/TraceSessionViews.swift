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
/// Also shows "Clearing previous events…" while a Clear that takes a while (many events) is deleting.
struct TraceStatusView: View {
    /// The session whose trace this shows.
    @ObservedObject var session: TraceSession
    
    /// Progress and Cancel while reading, clearing while a Clear deletes, or what was skipped.
    var body: some View {
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
