//
//  ContentView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 7/5/22.
//

import SwiftUI
import SystemExtensions
import SutroESFramework
import OSLog
import AppKit


/// Handles requesting app reboots and showing a TCC access alert.
class AgentCloseController: ObservableObject {
    @Published var showAlert = false
    
    /// Should the TCC alert be shown?
    func toggleQuitAlert() {
        showAlert.toggle()
    }
    
    /// Request that the app be re-launched over XPC by the persistent Security Extension
    func quitAgent(esm: EndpointSecurityManager) {
        esm.tccRequestAppReboot()
        NSApp.terminate(nil)
    }
}

// Custom button style for alert
struct AlertButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding()
            .background(configuration.isPressed ? Color.red.opacity(0.8) : Color.red)
            .foregroundColor(.white)
            .cornerRadius(10)
    }
}


// MARK: Primary App View
/// The primary view for Mac Monitor. Consisting of a toolbar and two tables.
///
/// In this view  the user can interact with Mac Monitor's primary functionality,
struct EventView: View {
    /// Get the system apperance
    @Environment(\.colorScheme) var colorMode
    
    /// Open a new "Event metadata" window
    @Environment(\.openWindow) private var eventFactsWindow
    
    /// Track everything going on with System Events and the Security Extension
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    
    /// Load user preferences from ``UserDefaults``
    @EnvironmentObject var userPrefs: UserPrefs
    
    
    
    /// Events from the EventStore (replaces Core Data @FetchRequest).
    ///
    /// The EventStore publishes events as they arrive from the Security Extension.
    /// We observe the store directly — no more Core Data managed object context.
    @ObservedObject private var eventStore = EventStore.shared
    
    
    
    /// Is a system trace occuring?
    @Binding var recordingEvents: Bool
    @State private var isBlinking: Bool = false
    
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
    
    /// The text to filter by in the context search field
    @Binding var filterText: String
    
    /// The query the user wants to filter the ``context`` field by.
    @State var submitedQuery: String = ""
    
    
    
    /// Implements our ability to request app re-launches over XPC by the Security Extension.
    ///
    /// This is done by ``AgentCloseController``.
    @StateObject private var agentTerminate = AgentCloseController()
    
    
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

    /// Should events be displayed in ascending order?
    @State private var ascending: Bool = false

    /// Filtered event indices for display — updated directly by background filter task.
    /// Total count of filtered events (uncapped). Used for status bar display.
    /// Unlike the previous `filteredIndices: [Int]` array, this avoids O(n) array
    /// allocation every update cycle (was ~1.2MB at 150K events).
    @State private var totalFilteredCount: Int = 0
    @State private var filteredEventIndices: [Int] = []
    /// Pre-filtered exec events — computed on background queue to avoid O(n) filter in view body.
    @State private var filteredExecEventIndices: [Int] = []
    /// Event-type counts for the mini-chart (lightweight, avoids decoded retention).
    @State private var chartEventTypeCounts: [String: Int] = [:]
    @State private var filterWorkItem: DispatchWorkItem?
    @State private var filterUpdateGeneration: UInt64 = 0
    
    /// Incremental filtering: track last processed index to avoid re-filtering all events
    @State private var lastProcessedIndex: Int = 0
    
    /// Flag to force full recompute when filters change (vs incremental for new events)
    @State private var needsFullRecompute: Bool = true
    
    /// Throttle state for UI updates (~5 FPS under load).
    ///
    /// ProcMon updates at 10-30 Hz for its lightweight virtual list. SwiftUI Table
    /// is much heavier per update, so we use a longer interval to avoid stacking
    /// layout passes on the main thread.
    @State private var lastFilterTime: Date = .distantPast
    @State private var hasPendingFilterUpdate: Bool = false
    
    /// Maximum events passed to the table.
    ///
    /// This app is an analysis tool and must retain full scrollback visibility,
    /// so we do not cap display rows.
    private static let tableDisplayLimit: Int = .max
    
    /// Cached lineage resolver (only rebuild on full recompute)
    @State private var cachedLineageResolver: ProcessLineageResolver?
    
    /// This more *rare* alert will be displayed when the the user launches the app.
    ///
    /// Usually what we'll do is check on app-launch and disable the start button.
    @State private var tccAlert: Bool = false
    
    
    /// Throttles filter updates to ~5 FPS for UI responsiveness.
    ///
    /// Full recomputes (filter changes) bypass the throttle for immediate response.
    /// Incremental updates (new events) are gated to reduce SwiftUI diff frequency,
    /// matching ProcMon's timer-coalesced update approach (~10-30 Hz).
    private func scheduleFilterUpdate() {
        // Full recomputes bypass throttle — filter changes need immediate response
        if needsFullRecompute {
            hasPendingFilterUpdate = false
            lastFilterTime = Date()
            executeFilterUpdate()
            return
        }
        
        let now = Date()
        let elapsed = now.timeIntervalSince(lastFilterTime)
        
        if elapsed >= 0.20 {
            // Enough time has passed — run immediately
            hasPendingFilterUpdate = false
            lastFilterTime = now
            executeFilterUpdate()
        } else if !hasPendingFilterUpdate {
            // Schedule a deferred run at the next throttle boundary
            hasPendingFilterUpdate = true
            let delay = 0.20 - elapsed
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                self.hasPendingFilterUpdate = false
                self.lastFilterTime = Date()
                self.executeFilterUpdate()
            }
        }
        // If hasPendingFilterUpdate is already true, a deferred run is already scheduled
    }
    
    /// Executes the background filter pass (index-only + optional context decode).
    ///
    /// Output is maintained as index arrays (oldest first) for efficient
    /// incremental appends without retaining full decoded event payloads.
    ///
    /// Two-pass filtering:
    /// 1. Index-only filter (fast, no decode)
    /// 2. Context filter with substring/regex support (requires decode)
    ///
    /// Performance strategy:
    /// - `totalFilteredCount` is a scalar tracking the full match count for the status bar.
    ///   This replaces the previous `filteredIndices: [Int]` array which caused O(n) allocations.
    /// - Display arrays are not capped; users must be able to scroll complete history.
    /// - Background filter updates are generation-guarded to prevent stale async writes.
    private func executeFilterUpdate() {
        filterWorkItem?.cancel()
        filterUpdateGeneration &+= 1

        let fullRecompute = needsFullRecompute
        let startIndex = fullRecompute ? 0 : lastProcessedIndex
        let generation = filterUpdateGeneration

        // Capture current values for the background closure.
        // Avoid snapshotting the entire index each update to keep memory bounded.
        let indexCount = eventStore.getIndexCount()
        let filters = allFilters
        let searchText = filterText.lowercased()
        let filterLongRunning = filteringLongRunningProcs
        let showMiniChart = viewMiniChart
        let showExecTable = processExecSelected
        let esm = systemExtensionManager
        let existingCount = totalFilteredCount

        // Build regex pattern for context filter if needed
        let contextPattern = buildContextPattern(from: searchText)

        var work: DispatchWorkItem!
        work = DispatchWorkItem {
            if work.isCancelled { return }

            let needsLineageResolver = filters.shouldIncludeProcessSubTrees &&
                (filters.rootIncludedInitiatingProcessPath != nil || filters.rootIncludedTargetProcessPath != nil)

            // Build or reuse lineage resolver only when lineage subtree filters are active.
            // This avoids retaining a large process graph when lineage filtering is not in use.
            let lineageResolver: ProcessLineageResolver?
            if needsLineageResolver {
                if fullRecompute || cachedLineageResolver == nil {
                    let lineageEntries = eventStore.getIndexEntries(range: 0..<indexCount)
                    let resolver = ProcessLineageResolver(indexEntries: lineageEntries) { hash in
                        eventStore.getPath(forHash: hash)
                    }
                    lineageResolver = resolver
                    DispatchQueue.main.async {
                        guard self.filterUpdateGeneration == generation else { return }
                        self.cachedLineageResolver = resolver
                    }
                } else {
                    lineageResolver = cachedLineageResolver
                }
            } else {
                lineageResolver = nil
                DispatchQueue.main.async {
                    guard self.filterUpdateGeneration == generation else { return }
                    self.cachedLineageResolver = nil
                }
            }

            if work.isCancelled { return }

            let initiatingLineageSet = filters.rootIncludedInitiatingProcessPath.flatMap { path in
                filters.shouldIncludeProcessSubTrees ?
                    lineageResolver?.computeLineageSet(includedPath: path, pathLookup: { eventStore.getPath(forHash: $0) }, includeAncestors: true) : nil
            }

            let targetLineageSet = filters.rootIncludedTargetProcessPath.flatMap { path in
                filters.shouldIncludeProcessSubTrees ?
                    lineageResolver?.computeLineageSet(includedPath: path, pathLookup: { eventStore.getPath(forHash: $0) }, includeAncestors: true) : nil
            }

            // PASS 1: Index-only filter (fast)
            var candidateIndices: [Int] = []
            let scanEnd = indexCount
            var scannedEntries: [EventIndexEntry] = []
            if startIndex < scanEnd {
                scannedEntries = eventStore.getIndexEntries(range: startIndex..<scanEnd)
                candidateIndices.reserveCapacity(scannedEntries.count)
            }

            for (offset, entry) in scannedEntries.enumerated() {
                if work.isCancelled { return }
                let i = startIndex + offset
                if isIndexEntryFiltered(
                    entry: entry,
                    filteringLongRunningProcs: filterLongRunning,
                    allFilters: filters,
                    systemExtensionManager: esm,
                    initiatingLineageSet: initiatingLineageSet,
                    targetLineageSet: targetLineageSet
                ) {
                    candidateIndices.append(i)
                }
            }

            // SHORT-CIRCUIT: If incremental update found no new matches, skip
            // the main-thread @State assignment entirely. This avoids pushing an
            // identical array into SwiftUI and triggering a redundant O(n) diff.
            // Full recomputes always proceed (filters changed, need fresh state).
            if !fullRecompute && candidateIndices.isEmpty {
                DispatchQueue.main.async {
                    guard self.filterUpdateGeneration == generation else { return }
                    self.lastProcessedIndex = indexCount
                }
                return
            }

            // PASS 2: Context filter (requires decode).
            var matchedIndices: [Int] = []
            var matchedExecIndices: [Int] = []
            var fullRecomputeChartCounts: [String: Int] = [:]
            var incrementalChartCounts: [String: Int] = [:]

            matchedIndices.reserveCapacity(candidateIndices.count)
            if showExecTable {
                matchedExecIndices.reserveCapacity(candidateIndices.count / 4)
            }

            if contextPattern != nil && !searchText.isEmpty {
                // Context filter: must decode all candidates to test context match.
                for idx in candidateIndices {
                    if work.isCancelled { return }
                    let offset = idx - startIndex
                    guard offset >= 0, offset < scannedEntries.count else { continue }
                    let entry = scannedEntries[offset]
                    guard let event = eventStore.getEvent(at: idx) else { continue }
                    if matchesContextFilter(event: event, pattern: contextPattern, searchText: searchText) {
                        matchedIndices.append(idx)
                        if showExecTable && entry.hasExec {
                            matchedExecIndices.append(idx)
                        }
                        if showMiniChart {
                            let key = chartKey(for: entry.esEventType)
                            if fullRecompute {
                                fullRecomputeChartCounts[key, default: 0] += 1
                            } else {
                                incrementalChartCounts[key, default: 0] += 1
                            }
                        }
                    }
                }
            } else {
                // No context filter: index-only matching.
                for idx in candidateIndices {
                    let offset = idx - startIndex
                    guard offset >= 0, offset < scannedEntries.count else { continue }
                    let entry = scannedEntries[offset]
                    matchedIndices.append(idx)
                    if showExecTable && entry.hasExec {
                        matchedExecIndices.append(idx)
                    }
                    if showMiniChart {
                        let key = chartKey(for: entry.esEventType)
                        if fullRecompute {
                            fullRecomputeChartCounts[key, default: 0] += 1
                        } else {
                            incrementalChartCounts[key, default: 0] += 1
                        }
                    }
                }
            }

            if work.isCancelled { return }

            let newFilteredCount = fullRecompute ? matchedIndices.count : existingCount + matchedIndices.count

            DispatchQueue.main.async {
                guard self.filterUpdateGeneration == generation else { return }
                self.totalFilteredCount = newFilteredCount
                if fullRecompute {
                    self.filteredEventIndices = matchedIndices
                    self.filteredExecEventIndices = showExecTable ? matchedExecIndices : []
                    self.chartEventTypeCounts = showMiniChart ? fullRecomputeChartCounts : [:]
                } else {
                    if !matchedIndices.isEmpty {
                        self.filteredEventIndices.append(contentsOf: matchedIndices)
                    }
                    if showExecTable && !matchedExecIndices.isEmpty {
                        self.filteredExecEventIndices.append(contentsOf: matchedExecIndices)
                    } else if !showExecTable {
                        self.filteredExecEventIndices = []
                    }
                    if showMiniChart {
                        if !incrementalChartCounts.isEmpty {
                            for (key, value) in incrementalChartCounts {
                                self.chartEventTypeCounts[key, default: 0] += value
                            }
                        }
                    } else {
                        self.chartEventTypeCounts = [:]
                    }
                }
                self.lastProcessedIndex = indexCount
                self.needsFullRecompute = false
            }
        }
        filterWorkItem = work
        DispatchQueue.global(qos: .userInteractive).async(execute: work)
    }

    /// Builds a regex pattern from the search text.
    /// Supports: plain text (substring), regex syntax if text starts with '/'
    private func buildContextPattern(from text: String) -> Regex<AnyRegexOutput>? {
        guard !text.isEmpty else { return nil }

        // If text starts with '/', treat as regex
        if text.hasPrefix("/") && text.count > 1 {
            let patternString = String(text.dropFirst())
            return try? Regex(patternString)
        }

        // Otherwise, substring match (case-insensitive)
        // Escape special regex characters for literal substring matching
        let escaped = text.replacingOccurrences(of: "[\\[\\]{}()*+?.\\\\^$|]", with: "\\\\$0", options: .regularExpression)
        return try? Regex("(?i)\(escaped)")
    }

    /// Checks if an event matches the context filter.
    private func matchesContextFilter(event: Message, pattern: Regex<AnyRegexOutput>?, searchText: String) -> Bool {
        guard let pattern = pattern else { return true }
        guard let context = event.context else { return false }
        return context.contains(pattern)
    }

    private func chartKey(for esEventType: String) -> String {
        var key = esEventType
        if key.hasPrefix("ES_EVENT_TYPE_NOTIFY_") {
            key = String(key.dropFirst("ES_EVENT_TYPE_NOTIFY_".count))
        } else if key.hasPrefix("ES_EVENT_TYPE_AUTH_") {
            key = String(key.dropFirst("ES_EVENT_TYPE_AUTH_".count))
        } else if key.hasPrefix("ES_EVENT_TYPE_") {
            key = String(key.dropFirst("ES_EVENT_TYPE_".count))
        }

        switch key {
        case "BTM_LAUNCH_ITEM_ADD":
            return "LAUNCH_ITEM_ADD"
        case "BTM_LAUNCH_ITEM_REMOVE":
            return "LAUNCH_ITEM_REMOVE"
        case "LW_SESSION_UNLOCK":
            return "LW_UNLOCK"
        case "LW_SESSION_LOGIN":
            return "LW_LOGIN"
        case "AUTHORIZATION_PETITION":
            return "AUTH_PETITION"
        case "AUTHORIZATION_JUDGEMENT":
            return "AUTH_JUDGEMENT"
        default:
            return key
        }
    }

    /// The string displaying the number of System Events collected over the course of the trace
    private var eventCountString: AttributedString {
        let hasActiveFilters = allFilters.totalFilters() + (filteringLongRunningProcs ? 1 : 0) > 0

        if !hasActiveFilters {
            return try! AttributedString(markdown: "**Events** `\(eventStore.eventCount)`")
        }

        let totalCount = eventStore.eventCount
        let filteredCount = totalFilteredCount
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
        systemExtensionManager.eventStore.clearEvents()
        
        // Reset filter state
        totalFilteredCount = 0
        filteredEventIndices = []
        filteredExecEventIndices = []
        chartEventTypeCounts = [:]
        lastProcessedIndex = 0
        needsFullRecompute = true
        cachedLineageResolver = nil
        lastFilterTime = .distantPast
        hasPendingFilterUpdate = false
        
        if sentinel {
            recordingEvents = true
            systemExtensionManager.startRecordingEvents()
            sentinel = false
        }
    }
    
    private var eventsTable: some View {
        SystemEventsNSTableContainerView(
            messageIndicesInScope: filteredEventIndices,
            execMessageIndicesInScope: filteredExecEventIndices,
            chartEventTypeCounts: chartEventTypeCounts,
            unifiedViewSelected: $unifiedViewSelected,
            viewExec: $processExecSelected,
            viewMiniChart: $viewMiniChart,
            ascending: $ascending,
            allFilters: $allFilters,
            messageSelections: $eventSelection
        )
        .environmentObject(systemExtensionManager)
        .environmentObject(userPrefs)
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            eventsTable
        }
        .toolbar {
            ToolbarItemGroup(placement: .principal) {
                if #unavailable(macOS 14) {
                    VenturaStartButton(recordingEvents: $recordingEvents, confirmClear: $confirmClear)
                        .environmentObject(systemExtensionManager)
                        .environmentObject(agentTerminate)
                        .environmentObject(userPrefs)
                } else {
                    SonomaStartButton(recordingEvents: $recordingEvents, confirmClear: $confirmClear)
                        .environmentObject(systemExtensionManager)
                        .environmentObject(agentTerminate)
                        .environmentObject(userPrefs)
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
                    if userPrefs.lifecycleWarnBeforeClear {
                        confirmClear.toggle()
                    } else {
                        clearSystemEventsUI()
                    }
                }) {
                    Label("Clear", systemImage: "clear")
                        .labelStyle(.titleAndIcon)
                        .padding([.leading, .trailing], 5)
                }
                .disabled(eventStore.eventCount == 0)
            }
            
            ToolbarItem(placement: .principal) {
                Button {
                    filteredTelemetryShown.toggle()
                } label: {
                    Text("Filters `\(allFilters.totalFilters() + (filteringLongRunningProcs ? 1 : 0) + (filterPlatform ? 1 : 0))`")
                        .padding([.leading, .trailing], 5)
                }.sheet(isPresented: $filteredTelemetryShown, content: {
                    FilterView(
                        allFilters: $allFilters,
                        filteredTelemetryShown: $filteredTelemetryShown,
                        filterSelection: $filterSelection,
                        filteringLongRunningProcs: $filteringLongRunningProcs,
                        eventMaskEnabled: $eventMaskEnabled,
                        filterPlatform: $filterPlatform
                    )
                    .environmentObject(systemExtensionManager)
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
                
                Circle()
                    .fill(recordingEvents ? Color.green : Color.red)
                    .shadow(color: Color.green, radius: 0.5)
                    .opacity(recordingEvents ? 0.85 : 0)
                    .scaleEffect(recordingEvents ? 1.25 : 1)
                    .animation(.linear(duration: 0.3), value: recordingEvents)
                    .help(recordingEvents ? "Recording system events" : "Not recording system events")
                    .padding(.trailing)
                
                Spacer()
            }
        }
        .searchable(text: $filterText, prompt: "Filter by context")
        .onChange(of: eventStore.eventCount) { newCount in
            // Detect programmatic store clear (count decreased → reset incremental state)
            if newCount < lastProcessedIndex {
                lastProcessedIndex = 0
                needsFullRecompute = true
                totalFilteredCount = 0
                filteredEventIndices = []
                filteredExecEventIndices = []
                chartEventTypeCounts = [:]
                cachedLineageResolver = nil
            }
            scheduleFilterUpdate()
        }
        .onChange(of: allFilters) { _ in
            needsFullRecompute = true
            lastProcessedIndex = 0
            cachedLineageResolver = nil
            scheduleFilterUpdate()
        }
        .onChange(of: filterText) { _ in
            needsFullRecompute = true
            lastProcessedIndex = 0
            scheduleFilterUpdate()
        }
        .onChange(of: viewMiniChart) { _ in
            needsFullRecompute = true
            scheduleFilterUpdate()
        }
        .onChange(of: processExecSelected) { _ in
            needsFullRecompute = true
            scheduleFilterUpdate()
        }
        .onChange(of: filteringLongRunningProcs) { _ in
            needsFullRecompute = true
            lastProcessedIndex = 0
            cachedLineageResolver = nil
            scheduleFilterUpdate()
        }
        .onAppear {
            if !CommandLine.arguments.contains("--deactive-security-extension") {
                systemExtensionManager.activateSystemExtension()
                
                switch(systemExtensionManager.connectionResult) {
                case .notPermitted:
                    os_log("💾 [ES new client result] TCC FDA required!")
                    tccAlert = true
                    break
                case .internalSubsystem:
                    os_log("😥 [ES new client result] internalSubsystem error!")
                    break
                case .invalidArgument:
                    os_log("🤔 [ES new client result] invalidArgument error!")
                    break
                case .notEntitled:
                    os_log("🔒 [ES new client result] ES entitlement not found!")
                    break
                case .tooManyClients:
                    os_log("🍬 [ES new client result] tooManyClients error!")
                    break
                case .success:
                    os_log("⚡️ [ES new client result] Success!")
                    break
                case .notPrivileged:
                    os_log("😬 [ES new client result] notPrivileged!")
                    break
                case .waiting:
                    os_log("🥱 [ES new client result] waiting...")
                    break
                default:
                    os_log("🤔 [ES new client result] Unknown error!")
                    break
                }
            }
            
            // We're not recording events at app launch
            recordingEvents = false
            
            // Populate initial filtered events (onChange doesn't fire for initial values)
            scheduleFilterUpdate()
            
            #if DEBUG
            // Launch automated stress test if configured via command-line arguments.
            // The XCUITest runner sets these arguments before launching the app.
            if let config = StressTestConfig.fromCommandLine() {
                // Wait for the UI to settle before starting injection.
                // This ensures SwiftUI has completed its initial layout pass
                // and the main thread monitor captures realistic latencies.
                DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
                    let runner = StressTestRunner(config: config)
                    runner.run()
                }
            }
            #endif
        }
        .alert("The Security Extension does not have full disk access!", isPresented: $tccAlert) {
            Button("Open System Settings") {
                tccAlert = false
                NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
            }
        }
    }
}

/// Filters an index entry without decoding the full event.
/// Context filtering is handled separately in a second pass after decode.
private func isIndexEntryFiltered(
    entry: EventIndexEntry,
    filteringLongRunningProcs: Bool,
    allFilters: Filters,
    systemExtensionManager: EndpointSecurityManager,
    initiatingLineageSet: Set<String>?,
    targetLineageSet: Set<String>?
) -> Bool {
    // Lineage inclusion filter
    let inclusionFilterActive = allFilters.rootIncludedInitiatingProcessPath != nil ||
                                allFilters.rootIncludedTargetProcessPath != nil
    
    if inclusionFilterActive {
        var matchesAnInclusionFilter = false
        
        let initiatingToken = entry.auditTokenString
        
        // Check initiating process
        if let _ = allFilters.rootIncludedInitiatingProcessPath {
            if allFilters.shouldIncludeProcessSubTrees {
                if initiatingLineageSet?.contains(initiatingToken) == true {
                    matchesAnInclusionFilter = true
                }
            } else if let path = systemExtensionManager.eventStore.getPath(forHash: entry.executablePathHash),
                      path == allFilters.rootIncludedInitiatingProcessPath {
                matchesAnInclusionFilter = true
            }
        }
        
        if !matchesAnInclusionFilter, let _ = allFilters.rootIncludedTargetProcessPath {
            if allFilters.shouldIncludeProcessSubTrees {
                if initiatingLineageSet?.contains(initiatingToken) == true {
                    matchesAnInclusionFilter = true
                }
            } else if let path = systemExtensionManager.eventStore.getPath(forHash: entry.executablePathHash),
                      path == allFilters.rootIncludedTargetProcessPath {
                matchesAnInclusionFilter = true
            }
        }
        
        // Check exec target
        if !matchesAnInclusionFilter, let targetToken = entry.targetAuditTokenString {
            if let _ = allFilters.rootIncludedInitiatingProcessPath {
                if allFilters.shouldIncludeProcessSubTrees {
                    if initiatingLineageSet?.contains(targetToken) == true {
                        matchesAnInclusionFilter = true
                    }
                }
            }
            
            if !matchesAnInclusionFilter, let _ = allFilters.rootIncludedTargetProcessPath {
                if allFilters.shouldIncludeProcessSubTrees {
                    if targetLineageSet?.contains(targetToken) == true {
                        matchesAnInclusionFilter = true
                    }
                }
            }
        }
        
        if !matchesAnInclusionFilter { return false }
    }
    
    // MARK: Non-lineage filters:
    if filteringLongRunningProcs,
       entry.darwinTime.timeIntervalSince1970 < systemExtensionManager.clientConnectDT.timeIntervalSince1970 {
        return false
    }
    
    if allFilters.events.contains(entry.esEventType) { return false }
    if let user = entry.euidHuman, allFilters.userIDs.contains(user) { return false }
    if let path = systemExtensionManager.eventStore.getPath(forHash: entry.executablePathHash),
       allFilters.initiatingPaths.contains(path) { return false }
    
    if let targetHash = entry.targetPathHash,
       let targetPath = systemExtensionManager.eventStore.getPath(forHash: targetHash) {
        if allFilters.targetPaths.contains(targetPath) ||
           !allFilters.targetPaths.filter({ targetPath.contains($0) }).isEmpty {
            return false
        }
    }
    
    return true
}
