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


/// Handles requesting app reboots and showing a TCC access alert.
class AgentCloseController: ObservableObject {
    @Published var showAlert = false
    
    /// Should the TCC alert be shown?
    func toggleQuitAlert() {
        showAlert.toggle()
    }
    
    /// Request that the app be re-launched once it has quit
    func quitAgent(esm: EndpointSecurityManager) {
        esm.requestAgentRelaunch()
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
    /// Track everything going on with System Events and the Security Extension
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    
    /// Load user preferences from ``UserDefaults``
    @EnvironmentObject var userPrefs: UserPrefs
    
    
    
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
    
    /// The text to filter by in the context search field
    @Binding var filterText: String
    
    
    
    /// Implements our ability to relaunch the app (e.g. after Full Disk Access is granted).
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
    
    /// This more *rare* alert will be displayed when the the user launches the app.
    ///
    /// Usually what we'll do is check on app-launch and disable the start button.
    @State private var tccAlert: Bool = false
    
    
    /// Everything that decides which events the event tables show.
    private var filterSpec: EventFilterSpec {
        EventFilterSpec(
            filters: allFilters,
            searchText: filterText,
            filteringLongRunningProcs: filteringLongRunningProcs,
            clientConnectDT: systemExtensionManager.clientConnectDT
        )
    }
    
    /// The number of System Events in the store.
    private var totalEventCount: Int { eventQueries.totalCount }
    
    /// The string displaying the number of System Events collected over the course of the trace
    private var eventCountString: AttributedString {
        let hasActiveFilters = allFilters.totalFilters() + (filteringLongRunningProcs ? 1 : 0) > 0
        
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
    
    var body: some View {
        VStack(alignment: .leading) {
            AppKitEventTablesView(
                model: eventQueries,
                allFilters: $allFilters,
                messageSelections: $eventSelection,
                unifiedViewSelected: $unifiedViewSelected,
                viewExec: $processExecSelected,
                viewMiniChart: $viewMiniChart
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
                .disabled(totalEventCount == 0)
                
                
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
        .onAppear {
            if !CommandLine.arguments.contains("--deactivate-security-extension") {
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
        }
        .alert("The Security Extension does not have full disk access!", isPresented: $tccAlert) {
            Button("Open System Settings") {
                tccAlert = false
                NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
            }
        }
    }
}

