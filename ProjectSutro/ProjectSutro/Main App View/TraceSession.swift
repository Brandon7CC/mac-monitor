//
//  TraceSession.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import SwiftUI
import AppKit
import SutroESFramework


// MARK: - Trace session
/// What Mac Monitor's windows show: a live recording, or a trace file opened with File > Open Trace… (#38).
///
/// One trace at a time, like Process Monitor: every main window is a view of the same event store, so opening a trace
/// replaces the events in all of them. Clear and Start close the trace and return to recording: any Clear returns the
/// store to live (``CoreDataController/clearSystemEvents(source:)``), which the session follows through
/// ``CoreDataController/eventsWillClear``. An open trace is a copy of a file that's still on disk, so replacing or closing
/// it never asks. Replacing recorded events asks first, under the same "warn before clearing" setting as Clear.
///
/// A file is checked (``TraceImporter/preflight(_:)``) in the background before anything is cleared. Opening another file
/// or a Clear meanwhile drops it.
///
/// Main thread only.
final class TraceSession: ObservableObject {
    /// The trace being read or shown, `nil` while live.
    @Published private(set) var url: URL?
    /// How far reading the file has got, while it's being read.
    @Published private(set) var progress: TraceImporter.Progress?
    /// How reading the file ended, once it has.
    @Published private(set) var summary: TraceImporter.Summary?
    /// Is a Clear still deleting the previous events, half a second after it started?
    @Published private(set) var isClearing = false
    /// File > Open Recent, newest first.
    @Published private(set) var recents: [URL] = NSDocumentController.shared.recentDocumentURLs
    /// The file being read.
    @Published private var importer: TraceImporter?
    /// Main windows showing the events, counted by `EventView`: with none, a trace opened from the File menu opens one.
    var mainWindows = 0
    
    /// The event store every window shows.
    private let store: CoreDataController
    /// The store's Clear notifications, and the app becoming active (Open Recent may have changed meanwhile).
    private var observers: [NSObjectProtocol] = []
    /// Opens started, and Clears: a file whose check finishes after either has started is dropped.
    private var opens = 0
    
    /// - Parameter store: The event store.
    init(store: CoreDataController = .shared) {
        self.store = store
        let center = NotificationCenter.default
        observers = [
            center.addObserver(forName: CoreDataController.eventsWillClear, object: store, queue: nil) { [weak self] _ in
                self?.storeWillClear()
            },
            center.addObserver(forName: CoreDataController.eventsDidClear, object: store, queue: nil) { [weak self] _ in
                self?.isClearing = store.isClearing
            },
            center.addObserver(forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in
                self?.refreshRecents()
            },
        ]
    }
    
    /// Stop following the store's Clears and the app.
    deinit { observers.forEach(NotificationCenter.default.removeObserver) }
    
    /// Are recorded events showing (rather than a trace)?
    var isLive: Bool { url == nil }
    /// Is a trace being read?
    var isOpening: Bool { importer != nil }
    
    /// The window title: the trace's name, or the app's.
    var title: String { url?.lastPathComponent ?? "Mac Monitor" }
    
    /// The window subtitle: how far reading has got, or what the trace holds. Empty while live.
    var subtitle: String {
        if isOpening {
            return progress.map { "Opening… \(Self.bytes($0.bytesRead)) of \(Self.bytes($0.totalBytes))" } ?? "Opening…"
        }
        guard let summary else { return "" }
        var parts = [Self.counted(summary.saved, "event")]
        if let range = summary.timeRange { parts.append(Self.interval.string(from: range.lowerBound, to: range.upperBound)) }
        if let stoppedAt = summary.stoppedAt { parts.append("stopped at \(Self.percent(stoppedAt))") }
        return parts.joined(separator: " · ")
    }
    
    // MARK: Opening
    /// File > Open Trace…: choose a file and open it.
    ///
    /// Any file can be chosen: a trace is recognized by its content, and eslogger writes to whatever file its output is
    /// redirected to.
    ///
    /// - Parameters:
    ///   - recording: The app's recording state, stopped if the trace replaces the recording.
    ///   - esm: Stops the recording.
    ///   - showWindow: Opens a main window, called if none is open once the trace starts opening.
    func chooseTrace(recording: Binding<Bool>, esm: EndpointSecurityManager, showWindow: @escaping () -> Void = {}) {
        let panel = NSOpenPanel()
        panel.title = "Open Trace"
        panel.message = "Choose an eslogger or Mac Monitor JSON trace."
        panel.prompt = "Open"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        open(url, recording: recording, esm: esm, showWindow: showWindow)
    }
    
    /// Open a trace from the Open panel, Open Recent, Finder's Open With, `open -a`, or a drop on a window.
    ///
    /// The file is checked in the background before anything is cleared, so one that isn't a trace never costs the events
    /// on screen.
    ///
    /// - Parameters:
    ///   - url: The trace.
    ///   - recording: The app's recording state, stopped if the trace replaces the recording.
    ///   - esm: Stops the recording.
    ///   - showWindow: Opens a main window, called if none is open once the trace starts opening.
    func open(_ url: URL, recording: Binding<Bool>, esm: EndpointSecurityManager, showWindow: @escaping () -> Void = {}) {
        opens += 1
        let ticket = opens
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let checked = Swift.Result { try TraceImporter.preflight(url) }
            DispatchQueue.main.async {
                guard let self, self.opens == ticket else { return }
                switch checked {
                case .success: self.start(url, recording: recording, esm: esm, showWindow: showWindow)
                case .failure(let error):
                    self.refreshRecents()
                    Self.alert(cantOpen: url, error)
                }
            }
        }
    }
    
    /// Replace the events on screen with a trace that has passed its check, once the user agrees (unless another file
    /// or a Clear came first while they were asked).
    ///
    /// - Parameters:
    ///   - url: The trace.
    ///   - recording: The app's recording state, stopped if the trace replaces the recording.
    ///   - esm: Stops the recording.
    ///   - showWindow: Opens a main window, called if none is open.
    private func start(_ url: URL, recording: Binding<Bool>, esm: EndpointSecurityManager, showWindow: () -> Void) {
        let ticket = opens
        guard confirmReplacingRecordedEvents(with: url, recording: recording.wrappedValue), opens == ticket else { return }
        if recording.wrappedValue {
            recording.wrappedValue = false
            esm.cleanup()
            esm.stopRecordingEvents()
        }
        NSDocumentController.shared.noteNewRecentDocumentURL(url)
        refreshRecents()
        
        /// Reports from a trace that's since been replaced or closed are ignored.
        var importer: TraceImporter?
        importer = store.openTrace(at: url) { [weak self] progress in
            guard let self, self.importer === importer else { return }
            self.progress = progress
        } completion: { [weak self] summary in
            guard let self, self.importer === importer else { return }
            self.finished(summary)
        }
        (self.importer, self.url, progress, summary) = (importer, url, nil, nil)
        if mainWindows == 0 { showWindow() }
    }
    
    /// Open the first file dropped on a window.
    ///
    /// - Parameters:
    ///   - providers: The dropped items.
    ///   - recording: The app's recording state.
    ///   - esm: Stops the recording.
    /// - Returns: Whether the drop held a file.
    func open(dropped providers: [NSItemProvider], recording: Binding<Bool>, esm: EndpointSecurityManager) -> Bool {
        guard let provider = providers.first(where: { $0.canLoadObject(ofClass: URL.self) }) else { return false }
        _ = provider.loadObject(ofClass: URL.self) { url, _ in
            guard let url, url.isFileURL else { return }
            DispatchQueue.main.async { self.open(url, recording: recording, esm: esm) }
        }
        return true
    }
    
    /// Cancel: stop reading the file and keep the events read so far.
    func stop() { importer?.stop() }
    
    /// File > Open Recent > Clear Menu.
    func clearRecents() {
        NSDocumentController.shared.clearRecentDocuments(nil)
        recents = []
    }
    
    /// Read File > Open Recent again: files moved or deleted since are found or dropped (`NSDocumentController` keeps
    /// bookmarks to them).
    private func refreshRecents() {
        let urls = NSDocumentController.shared.recentDocumentURLs
        if urls != recents { recents = urls }
    }
    
    /// A Clear started, which drops a file still being checked. One that returns the store to live (the toolbar's Clear,
    /// Start) closes the trace. A Clear still deleting after half a second shows "Clearing previous events…" (most finish
    /// well before).
    private func storeWillClear() {
        opens += 1
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
            guard let self else { return }
            self.isClearing = self.store.isClearing
        }
        guard store.source == .live else { return }
        (importer, url, progress, summary) = (nil, nil, nil, nil)
    }
    
    /// Reading the file ended.
    ///
    /// - Parameter summary: What was read.
    private func finished(_ summary: TraceImporter.Summary) {
        (importer, progress) = (nil, nil)
        guard summary.saved > 0 else {
            /// Nothing to show (cancelled before the first event, or the file changed since it was checked): back to an
            /// empty, live window.
            store.clearSystemEvents()
            if summary.stoppedAt == nil { Self.alert(cantOpen: summary.url, summary.error ?? TraceImporter.Failure.notATrace) }
            return
        }
        self.summary = summary
        if let error = summary.error { Self.alert(stoppedReading: summary, error) }
    }
    
    // MARK: Alerts
    /// Ask before a trace replaces recorded events, unless the user turned the warning off. A trace replacing a trace,
    /// or a recording that hasn't recorded anything yet, loses nothing and never asks.
    ///
    /// - Parameters:
    ///   - url: The trace.
    ///   - recording: Is Mac Monitor recording?
    /// - Returns: Whether to go ahead.
    private func confirmReplacingRecordedEvents(with url: URL, recording: Bool) -> Bool {
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
        if alert.suppressionButton?.state == .on { UserDefaults.standard.set(false, forKey: "lifecycleWarnBeforeClear") }
        return response == .alertFirstButtonReturn
    }
    
    /// The file can't be opened. Nothing has been cleared.
    ///
    /// - Parameters:
    ///   - url: The file.
    ///   - error: Why.
    private static func alert(cantOpen url: URL, _ error: Error) {
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
    private static func alert(stoppedReading summary: TraceImporter.Summary, _ error: Error) {
        let shown = summary.saved == 1 ? "The first event is shown." : "The first \(summary.saved.formatted()) events are shown."
        show("Mac Monitor stopped reading “\(summary.url.lastPathComponent)”.", "\(error.localizedDescription) \(shown)")
    }
    
    /// Show a warning.
    ///
    /// - Parameters:
    ///   - message: The alert's title.
    ///   - information: The alert's text.
    private static func show(_ message: String, _ information: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = message
        alert.informativeText = information
        alert.runModal()
    }
    
    // MARK: Formatting
    /// A number of bytes as a file size.
    ///
    /// - Parameter count: A number of bytes.
    /// - Returns: The size, e.g. "12.3 MB".
    private static func bytes(_ count: Int64) -> String { ByteCountFormatter.string(fromByteCount: count, countStyle: .file) }
    
    /// A fraction as a whole percentage.
    ///
    /// - Parameter fraction: From 0 to 1.
    /// - Returns: The percentage, e.g. "31%".
    static func percent(_ fraction: Double) -> String { fraction.formatted(.percent.precision(.fractionLength(0))) }
    
    /// A count of things, singular for one.
    ///
    /// - Parameters:
    ///   - count: How many.
    ///   - noun: What they are, singular: an "s" makes it plural.
    /// - Returns: For example "1 event" or "1,024 events".
    static func counted(_ count: Int, _ noun: String) -> String { "\(count.formatted()) \(noun)\(count == 1 ? "" : "s")" }
    
    /// A trace's time range, e.g. "Oct 2, 2026, 5:15:49 AM – 5:16:14 AM", in this Mac's time zone.
    private static let interval: DateIntervalFormatter = {
        let formatter = DateIntervalFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        return formatter
    }()
}


// MARK: - Event store
extension CoreDataController {
    /// Are the events showing read from a trace (File > Open Trace…) rather than recorded on this Mac?
    ///
    /// Muting, unsubscribing, and dropping platform binaries change what the Security Extension records, so they don't
    /// apply to a trace, whose file paths may also name files on another Mac. Main thread only.
    var isShowingTrace: Bool { source != .live }
}
