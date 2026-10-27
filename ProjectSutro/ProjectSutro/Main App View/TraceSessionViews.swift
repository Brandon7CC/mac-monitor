//
//  TraceSessionViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import SwiftUI
import AppKit
import UniformTypeIdentifiers
import SutroESFramework


// MARK: - Toolbar
/// The toolbar's trace status: what a trace held that isn't showing, or "Clearing previous events…" while a Clear
/// that takes a while (many events) is deleting. Reading a trace and saving one show in a window's sheet
/// (``TraceOpenSheet``, ``TraceSaveSheet``).
struct TraceStatusView: View {
    /// The session whose trace this shows.
    @ObservedObject var session: TraceSession
    
    /// Clearing while a Clear deletes, or what was skipped. Nothing while a trace is read.
    @ViewBuilder var body: some View {
        if session.isOpening {
            EmptyView()
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


// MARK: - Opening
/// The sheet a main window shows while a trace is read. It names the file and its folder, shows how much is read and
/// how many events, and offers Cancel, which keeps the events read so far.
struct TraceOpenSheet: View {
    @ObservedObject var session: TraceSession
    /// Was Cancel clicked? Reading stops at its next batch.
    @State private var isCancelled = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Opening Trace").font(.headline)
            if let url = session.url { TraceFileLabel(url: url) }
            if let progress = session.progress, !session.isClearing {
                ProgressView(value: progress.fraction)
                Text("\(TraceSession.bytes(progress.bytesRead)) of \(TraceSession.bytes(progress.totalBytes)) read · "
                     + TraceSession.counted(progress.events, "event"))
                    .font(.callout)
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
            } else {
                ProgressView().progressViewStyle(.linear)
                Text(isCancelled ? "Stopping…" : session.isClearing ? "Clearing previous events…" : "Reading…")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                Button("Cancel") {
                    isCancelled = true
                    session.stop()
                }
                .keyboardShortcut(.cancelAction)
                .disabled(isCancelled)
                .help("Stop reading and keep the events read so far")
            }
        }
        .padding(20)
        .frame(width: 440)
        .interactiveDismissDisabled()
    }
}


// MARK: - Saving
/// The sheet a main window shows while it saves a trace. It names the file and its folder, counts the events written,
/// and offers Cancel. A save that failed says why, with OK.
struct TraceSaveSheet: View {
    /// The save.
    let saving: TraceSession.Saving
    /// Stops the save, leaving the file as it was.
    let cancel: () -> Void
    /// Closes a failed save's sheet.
    let close: () -> Void

    /// The file being written.
    private var name: String { saving.url.lastPathComponent }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let failure = saving.failure {
                Label("Mac Monitor couldn't save “\(name)”.", systemImage: "exclamationmark.triangle.fill")
                    .font(.headline)
                    .symbolRenderingMode(.multicolor)
                Text(failure)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
                buttons { Button("OK", action: close).keyboardShortcut(.defaultAction) }
            } else {
                Text("Saving Trace").font(.headline)
                TraceFileLabel(url: saving.url)
                progress
                buttons {
                    Button("Cancel", action: cancel)
                        .keyboardShortcut(.cancelAction)
                        .disabled(saving.isCancelled)
                        .help(saving.replacing ? "Stop saving and leave “\(name)” as it was"
                              : "Stop saving without creating “\(name)”")
                }
            }
        }
        .padding(20)
        .frame(width: 440)
        .interactiveDismissDisabled()
    }

    /// The bar, by events written, and how many. Until the export knows its events, the bar is indeterminate.
    @ViewBuilder private var progress: some View {
        if let progress = saving.progress {
            ProgressView(value: progress.fraction)
            Text("\(progress.written.formatted()) of \(TraceSession.counted(progress.total, "event")) written")
                .font(.callout)
                .monospacedDigit()
                .foregroundStyle(.secondary)
        } else {
            ProgressView().progressViewStyle(.linear)
            Text(saving.isCancelled ? "Stopping…" : "Gathering the events…")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    /// - Parameter content: The sheet's buttons.
    /// - Returns: The buttons at the trailing edge.
    private func buttons<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        HStack {
            Spacer()
            content()
        }
    }
}


/// A trace file in a sheet: its icon, its name, and its folder.
struct TraceFileLabel: View {
    let url: URL

    var body: some View {
        HStack(spacing: 10) {
            Image(nsImage: NSWorkspace.shared.icon(for: UTType(filenameExtension: url.pathExtension) ?? .json))
                .resizable()
                .frame(width: 32, height: 32)
            VStack(alignment: .leading, spacing: 2) {
                Text(url.lastPathComponent).lineLimit(1).truncationMode(.middle)
                Text((url.deletingLastPathComponent().path as NSString).abbreviatingWithTildeInPath)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .help(url.path)
        }
    }
}


/// What a main window's sheet shows: a trace being read, or a save.
enum TraceSheet: Identifiable {
    case opening
    case saving(TraceSession.Saving)

    /// The same while a save's progress changes.
    var id: AnyHashable {
        switch self {
        case .opening: "opening"
        case .saving(let saving): saving.id
        }
    }
}


/// Makes a view a main window's content. The window counts as a main window, and shows the sheet for a trace being
/// read or a save when it belongs to the window.
private struct TraceSheetHost: ViewModifier {
    @ObservedObject var session: TraceSession
    @Environment(\.controlActiveState) private var activeState
    /// The window's identity, for as long as its content lives.
    @State private var window = UUID()

    func body(content: Content) -> some View {
        content
            .sheet(item: Binding { session.sheet(shownIn: window) } set: { _ in }) { sheet in
                switch sheet {
                case .opening: TraceOpenSheet(session: session)
                case .saving(let saving):
                    TraceSaveSheet(saving: saving, cancel: session.stopSaving, close: session.closeSaveFailure)
                }
            }
            .onAppear { session.windowAppeared(window, isKey: activeState == .key) }
            .onDisappear { session.windowDisappeared(window) }
            .onChange(of: activeState) { state in
                if state == .key { session.windowBecameKey(window) }
            }
    }
}


extension View {
    /// Makes the view a main window's content, which shows the sheet for a trace being read or a save when it belongs
    /// to its window.
    ///
    /// - Parameter session: The session that reads and saves traces.
    /// - Returns: The view, counted as a main window.
    func traceSheets(_ session: TraceSession) -> some View {
        modifier(TraceSheetHost(session: session))
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
