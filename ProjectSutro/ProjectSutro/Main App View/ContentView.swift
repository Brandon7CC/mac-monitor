//
//  ContentView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 7/5/22.
//

import SwiftUI
import CoreData
import SystemExtensions
import SutroESFramework
import OSLog
import AppKit
import UniformTypeIdentifiers


// MARK: Primary App View
/// The primary view for Mac Monitor. Consisting of a toolbar and two tables.
///
/// In this view  the user can interact with Mac Monitor's primary functionality,
struct EventView: View {
    /// Track everything going on with System Events and the Security Extension
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    
    /// Load user preferences from ``UserDefaults``
    @EnvironmentObject var userPrefs: UserPrefs
    
    /// A live recording, or an opened trace (File > Open Trace…).
    @EnvironmentObject var traceSession: TraceSession
    @Environment(\.openWindow) private var openWindow


    /// Fetches, filters, and counts the System Events for the event tables, the mini-chart, and the toolbar.
    @StateObject private var eventQueries = EventQueryModel()


    /// Is a system trace occuring?
    @Binding var recordingEvents: Bool
    
    /// Should the "System Security Unified" table be shown?
    @Binding var unifiedViewSelected: Bool
    /// Should the "Process Execution" table be shown?
    @Binding var processExecSelected: Bool
    /// Should the SwiftUI mini-chart be shown
    @Binding var viewMiniChart: Bool
    
    /// Are we filtering long processes which executed before Mac Monitor was started?
    ///
    // TODO: Implement long running process filtering
    @Binding var filteringLongRunningProcs: Bool


    /// The currently selected System Event (i.e. table row)
    @Binding var eventSelection: Set<ESMessage.ID>
    
    /// The search field's text: a context to find.
    @Binding var filterText: String
    /// The predicate the tables are filtered by, and the predicate editor's, shared with the editor's own window.
    @ObservedObject var search: EventSearchController


    /// Did opening the predicate editor beside the tables hide the mini chart, to show it again once it's gone?
    @State private var chartHiddenForEditor = false

    /// Is the requirements checklist showing?
    @State private var showsRequirements = false
    /// Has the checklist shown on its own? Only once a launch: after that, the toolbar says what's missing.
    @State private var requirementsShownOnce = false
    /// Was Mac Monitor launched only to deactivate the Security Extension? Then it never checks or activates it.
    private let deactivating = CommandLine.arguments.contains("--deactivate-security-extension")
    
    @State private var filterSelection = Set<String>()
    @State private var filteredTelemetryShown: Bool = false
    
    
    /// Track all filters offered by Mac Monitor
    @Binding var allFilters: Filters
    /// Is the event mask enabled?
    @Binding var eventMaskEnabled: Bool
    
    /// Should we ask the user to confirm before clearing System Events?
    @State private var confirmClear: Bool = false
    
    /// Should we filter out *most* events initiated by a platform binary?
    @State private var filterPlatform: Bool = false

    
    /// Shows, right away, what the Security Extension refused or left out of a mute asked for from an event's menu.
    private var showsEventMuteProblems: Binding<Bool> {
        Binding(get: { !systemExtensionManager.eventMuteProblems.isEmpty },
                set: { if !$0 { systemExtensionManager.eventMuteProblems = [] } })
    }
    
    
    /// Everything that decides which events the event tables show.
    private var filterSpec: EventFilterSpec {
        EventFilterSpec(
            filters: allFilters,
            searchText: filterText,
            recordPredicate: search.applied,
            filteringLongRunningProcs: filteringLongRunningProcs,
            /// Every event in a trace is older than this launch: the filter means nothing there.
            clientConnectDT: traceSession.isLive ? systemExtensionManager.clientConnectDT : .distantPast
        )
    }
    
    /// The number of System Events in the store.
    private var totalEventCount: Int { eventQueries.totalCount }
    
    /// The string displaying the number of System Events collected over the course of the trace
    private var eventCountString: AttributedString {
        let searching = !filterSpec.searchText.isEmpty || filterSpec.recordPredicate != nil
        let hasActiveFilters = allFilters.totalFilters() + (filteringLongRunningProcs ? 1 : 0) > 0 || searching
        
        if !hasActiveFilters {
            return try! AttributedString(markdown: "**Events** `\(totalEventCount)`")
        }
        
        let totalCount = totalEventCount
        let filteredCount = eventQueries.filteredCount
        let percentage = totalCount > 0 ? Double(filteredCount) / Double(totalCount) * 100.0 : 0.0
        
        return try! AttributedString(
            markdown: "**Events** `\(filteredCount)` (`\(String(format: "%.2f", percentage))%`)"
        )
    }
    
    /// Request that events be cleared from the PSC and reset the UI
    public func clearSystemEventsUI() {
        var sentinel: Bool = false
        if recordingEvents {
            recordingEvents = false
            
            sentinel = true
        }
        
        systemExtensionManager.cleanup()
        systemExtensionManager.stopRecordingEvents()
        systemExtensionManager.coreDataContainer.clearSystemEvents()
        
        if sentinel {
            recordingEvents = true
            systemExtensionManager.startRecordingEvents()
            sentinel = false
        }
    }
    
    /// Open a trace (File > Open Trace…), replacing the events on screen.
    ///
    /// - Parameter url: The trace, from Finder's Open With, `open -a`, or a drop on the window.
    private func openTrace(_ url: URL) {
        traceSession.open(url, recording: $recordingEvents, esm: systemExtensionManager)
    }
    
    /// The predicate editor, beside the tables while it's showing.
    private var predicateEditor: some View {
        PredicateEditorPane(search: search, model: eventQueries) { openWindow(id: ProjectSutroApp.schemaWindow) }
    }
    
    /// Show or hide the predicate editor (View ▸ Predicate Editor, ⌥⌘F), or bring its window forward.
    private func togglePredicateEditor() {
        if search.isPoppedOut { return openWindow(id: ProjectSutroApp.predicateEditorWindow) }
        if search.showsEditor { search.showsEditor = false } else { search.showEditor() }
    }
    
    var body: some View {
        /// A pane beside the tables, not an inspector: on macOS 26 an inspector puts the toolbar's blurred edge over
        /// the top of the window's content, the Unified table's title and headers.
        HStack(spacing: 0) {
            tables
            if search.showsEditor && !search.isPoppedOut {
                Divider()
                predicateEditor.frame(width: 440)
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: .togglePredicateEditor)) { _ in togglePredicateEditor() }
        .onAppear { search.queries = eventQueries }
        /// The editor beside the tables takes the mini chart's room, which comes back when the editor goes, unless
        /// it was shown again meanwhile.
        .onChange(of: search.showsEditor && !search.isPoppedOut) { beside in
            if beside, viewMiniChart {
                viewMiniChart = false
                chartHiddenForEditor = true
            } else if !beside, chartHiddenForEditor {
                viewMiniChart = true
                chartHiddenForEditor = false
            }
        }
        .onChange(of: viewMiniChart) { shown in
            if shown { chartHiddenForEditor = false }
        }
    }
    
    /// The event tables.
    private var tables: some View {
        VStack(alignment: .leading, spacing: 0) {
            AppKitEventTablesView(
                model: eventQueries,
                allFilters: $allFilters,
                messageSelections: $eventSelection,
                unifiedViewSelected: $unifiedViewSelected,
                viewExec: $processExecSelected,
                viewMiniChart: $viewMiniChart,
                openFile: openTrace
            )
            .environmentObject(systemExtensionManager)
            .environmentObject(userPrefs)
        }
        .onAppear { eventQueries.activate(spec: filterSpec) }
        .onChange(of: filterSpec) { spec in eventQueries.update(spec: spec) }
        /// The selected events are about to be deleted, so "Export telemetry" > "Selected events" mustn't offer them.
        .onReceive(NotificationCenter.default.publisher(for: CoreDataController.eventsWillClear)) { _ in eventSelection = [] }
        .toolbar {
            ToolbarItemGroup(placement: .principal) {
                if #unavailable(macOS 14) {
                    VenturaStartButton(recordingEvents: $recordingEvents, confirmClear: $confirmClear)
                        .environmentObject(systemExtensionManager)
                        .environmentObject(userPrefs)
                        .environmentObject(traceSession)
                } else {
                    SonomaStartButton(recordingEvents: $recordingEvents, confirmClear: $confirmClear)
                        .environmentObject(systemExtensionManager)
                        .environmentObject(userPrefs)
                        .environmentObject(traceSession)
                }
                
                // MARK: - Stop recording events
                Button(action: {
                    recordingEvents = false
                    Task {
                        systemExtensionManager.cleanup()
                        systemExtensionManager.stopRecordingEvents()
                    }
                }) {
                    Text("Stop")
                        .bold()
                        .padding([.leading, .trailing], 5)
                }
                .disabled(!recordingEvents)
            }
                
            // MARK: - Clear System Events
            ToolbarItem(placement: .principal) {
                Button(action: {
                    /// Closing a trace loses nothing: the file is still on disk.
                    if userPrefs.lifecycleWarnBeforeClear && traceSession.isLive {
                        confirmClear.toggle()
                    } else {
                        clearSystemEventsUI()
                    }
                }) {
                    Label("Clear", systemImage: "clear")
                        .labelStyle(.titleAndIcon)
                        .padding([.leading, .trailing], 5)
                }
                .disabled(totalEventCount == 0 && traceSession.isLive)
                .help(traceSession.isLive ? "" : "Close the trace")
                
                
            }
            
            ToolbarItem(placement: .principal) {
                Button {
                    filteredTelemetryShown.toggle()
                } label: {
                    Text("Filters `\(allFilters.totalFilters() + (filteringLongRunningProcs ? 1 : 0) + (filterPlatform ? 1 : 0))`")
                        .padding([.leading, .trailing], 5)
                }.sheet(isPresented: $filteredTelemetryShown, content: {
                    /// Opening the predicate editor puts the sheet away.
                    FilterView(
                        allFilters: $allFilters,
                        filteredTelemetryShown: $filteredTelemetryShown,
                        filterSelection: $filterSelection,
                        filteringLongRunningProcs: $filteringLongRunningProcs,
                        eventMaskEnabled: $eventMaskEnabled,
                        filterPlatform: $filterPlatform,
                        search: search
                    ) {
                        filteredTelemetryShown = false
                        if search.isPoppedOut || !search.showsEditor { togglePredicateEditor() }
                    }
                    .environmentObject(systemExtensionManager)
                    .environmentObject(traceSession)
                })
            }
            
            ToolbarItemGroup(placement: .status) {
                Button(action: {
                    viewMiniChart.toggle()
                }) {
                    Label("Mini-chart", systemImage: "chart.bar")
                        .padding([.leading, .trailing], 5)
                        .labelStyle(.iconOnly)
                }
                .disabled(unifiedViewSelected ? false : true)
                
                Text(eventCountString)
                    .padding([.trailing])
                
                TraceStatusView(session: traceSession)
                
                Circle()
                    .fill(recordingEvents ? Color.green : Color.red)
                    .shadow(color: Color.green, radius: 0.5)
                    .opacity(recordingEvents ? 0.85 : 0)
                    .scaleEffect(recordingEvents ? 1.25 : 1)
                    .animation(.linear(duration: 0.3), value: recordingEvents)
                    .help(recordingEvents ? "Recording system events" : "Not recording system events")
                    .padding(.trailing)
            }
        }
        .toolbar {
            /// Puts the search field and the predicate editor's button at the trailing edge. macOS 13 centers the
            /// principal and status items together, a status group's own spacer with them, and lays what follows
            /// right after them.
            ToolbarItemGroup(placement: .primaryAction) { Spacer() }
            /// The context search field, which narrows a predicate's matches.
            ToolbarItem(placement: .primaryAction) {
                EventSearchField(text: $filterText, narrowsPredicate: search.applied != nil)
                    .frame(width: 300)
            }
            /// Its own glass, apart from the search field's.
            if #available(macOS 26.0, *) {
                ToolbarSpacer(.fixed, placement: .primaryAction)
            }
            /// The predicate editor's button, right of the search field.
            ToolbarItem(placement: .primaryAction) {
                Button(action: togglePredicateEditor) {
                    Label("Predicate Editor", systemImage: "sidebar.right")
                }
                .help(search.applied.map {
                    "Predicate Editor (⌥⌘F): filtering by \(EventSearchController.oneLine($0.source))"
                } ?? "Predicate Editor (⌥⌘F)")
            }
        }
        .navigationTitle(traceSession.title)
        .navigationSubtitle(traceSession.subtitle)
        .background { TraceDocument(url: traceSession.url) }
        /// Finder's Open With and `open -a`: SwiftUI hands the first file to this window (see `AppDelegate` for the
        /// rest).
        .onOpenURL { url in
            guard url.isFileURL else { return }
            openTrace(url)
        }
        /// Drops outside the event tables (which take file drops themselves, see ``AppKitEventTable``).
        .onDrop(of: [.fileURL], isTargeted: nil) { providers in
            traceSession.open(dropped: providers, recording: $recordingEvents, esm: systemExtensionManager)
        }
        /// Counted so a trace opened from the File menu with no main window open gets one.
        .onAppear { traceSession.mainWindows += 1 }
        .onDisappear { traceSession.mainWindows -= 1 }
        /// Activates the Security Extension only if it's running: otherwise the checklist's Install button does, when
        /// macOS's prompt to open System Settings follows from it.
        .onAppear {
            guard !deactivating else { return }
            systemExtensionManager.checkExtensionAtLaunch()
        }
        /// Look again whenever Mac Monitor comes to the front, such as back from System Settings.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            guard !deactivating else { return }
            systemExtensionManager.refreshRequirements()
        }
        /// Show the checklist on its own once, as soon as it's known that something is missing.
        .onChange(of: systemExtensionManager.requirements) { requirements in
            guard !deactivating, !requirementsShownOnce, requirements.isSettled, !requirements.isReady else { return }
            requirementsShownOnce = true
            showsRequirements = true
        }
        .sheet(isPresented: $showsRequirements) {
            RequirementsView().environmentObject(systemExtensionManager)
        }
        .alert("Saved mute set", isPresented: showsEventMuteProblems,
               actions: { Button("OK", role: .cancel, action: {}) },
               message: { Text(systemExtensionManager.eventMuteProblems.joined(separator: "\n\n")) })
    }
}

