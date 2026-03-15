//
//  SystemEventFactsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework



struct CodeSigningDetailsView: View {
    var selectedMessage: ESMessage
    
    var body: some View {
        // Exec event code signing information
        if let exec = selectedMessage.event.exec {
            Section("**Target process signing status**") {
                if exec.target.is_adhoc_signed {
                    Text("  Adhoc Signed  ").background(Capsule().fill(.red).opacity(0.3)).padding(1)
                } else if exec.target.signing_id != nil {
                    Text("  \(exec.target.signing_id!)  ").background(Capsule().fill(.blue).opacity(0.3)).padding(1)
                } else {
                    Text("  Validly signed  ").background(Capsule().fill(.blue).opacity(0.3)).padding(1)
                }
            }.textSelection(.enabled)
        }
    }
}


struct SystemEventDetailsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.openWindow) private var openEventJSON
    
    var selectedMessage: ESMessage
    @State private var targetMetadataExpanded: Bool = true
    
    var body: some View {
        List {
            SystemTargetProcessView(selectedMessage: selectedMessage).environmentObject(systemExtensionManager)
        }.textSelection(.enabled)
    }
}


// MARK: - Event Facts tab view
struct SystemEventFactsView : View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    
    @EnvironmentObject var userPrefs: UserPrefs
    
    
    @Binding var allFilters: Filters
    @State private var viewEnriched: Bool = false
    var selectedMessage: ESMessage
    
    private enum EventTabs: Hashable {
        case metadata, telemetry, enrichment, initiating, plist, script
    }
    
    /// Process groups loaded async
    @State private var procGroup: [Message] = []
    @State private var procSessionGroup: [Message] = []
    @State private var correlatedEvents: [Message] = []
    @State private var isLoadingDerivedData: Bool = true
    
    private var groupsEventCount: Int {
        procGroup.count + procSessionGroup.count
    }

    private var groupToShow: Groups {
        !procGroup.isEmpty ? Groups.process : Groups.session
    }
    
    var body: some View {
        TabView {
            // MARK: Event Facts tab view metadata view
            VStack(alignment: .leading) {
                SystemEventDetailsView(selectedMessage: selectedMessage)
            }
            .padding(.bottom)
            .tabItem{ Text("Metadata") }
            .tag(EventTabs.metadata)
            
            // MARK: Script Tab
            if let exec = selectedMessage.event.exec,
               let content = exec.script_content,
               let path = exec.resolved_script_path,
               !content.isEmpty {
                VStack(alignment: .leading) {
                    FileContentView(path: path, content: content)
                }
                .tabItem{ Text("Script") }
                .tag(EventTabs.script)
            }
            
            // MARK: PLIST Tab
            if let event = selectedMessage.event.btm_launch_item_add,
               let plist = event.item.plist_contents {
                if !plist.isEmpty {
                    VStack(alignment: .leading) {
                        FileContentView(
                            path: event.item.item_path,
                            content: plist
                        )
                    }
                    .tabItem{ Text("PLIST") }
                    .tag(EventTabs.plist)
                }
            }
            
            // MARK: Enrichment view
            if !isLoadingDerivedData && correlatedEvents.count > 1 {
                VStack(alignment: .leading) {
                    SystemEnrichedEventView(
                        allFilters: $allFilters,
                        selectedMessage: selectedMessage,
                        correlatedEvents: correlatedEvents
                    )
                    .environmentObject(systemExtensionManager)
                    .environmentObject(userPrefs)
                }
                .tabItem{ Text("Correlation") }
                .tag(EventTabs.enrichment)
            }
            
            // MARK: Process Groups
            if isLoadingDerivedData || !procSessionGroup.isEmpty || !procGroup.isEmpty {
                VStack(alignment: .leading) {
                    if isLoadingDerivedData {
                        HStack {
                            ProgressView()
                            Text("Loading process groups...")
                        }
                        .padding()
                    } else {
                        SystemEventGroupTableViews(
                            allFilters: $allFilters,
                            selectedMessage: selectedMessage,
                            processGroup: procGroup,
                            sessionGroup: procSessionGroup
                        )
                    }
                }
                .tabItem{ Text("Groups") }
                .tag(EventTabs.enrichment)
            }
            
            // MARK: Initating process view
            VStack(alignment: .leading) {
                SystemInitiatingProcessView(selectedMessage: selectedMessage)
                    .textSelection(.enabled)
            }
            .tabItem{ Text("Parent") }
            .tag(EventTabs.initiating)
            
            // MARK: JSON view
            VStack(alignment: .leading) {
                SystemEventJSONView(selectedMessage: selectedMessage)
            }
            .tabItem{ Text("JSON") }
            .tag(EventTabs.telemetry)
        }
        .padding(.all)
        .onAppear {
            loadDerivedDataAsync()
        }
    }
    
    private func loadDerivedDataAsync() {
        isLoadingDerivedData = true
        Task {
            async let group = systemExtensionManager.eventStore.getProcGroupAsync(for: selectedMessage)
            async let session = systemExtensionManager.eventStore.getProcSessionGroupAsync(for: selectedMessage)
            async let correlated = systemExtensionManager.eventStore.getCorrelatedEventsAsync(for: selectedMessage)
            
            let (loadedGroup, loadedSession, loadedCorrelated) = await (group, session, correlated)
            
            await MainActor.run {
                self.procGroup = loadedGroup
                self.procSessionGroup = loadedSession
                self.correlatedEvents = loadedCorrelated
                self.isLoadingDerivedData = false
            }
        }
    }
}


struct AppWrapperForFacts: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    @Environment(\.openWindow) private var openEventFacts

    /// The event to display, looked up from EventStore by ID (replaces @FetchRequest)
    private let eventID: UUID
    @ObservedObject private var eventStore = EventStore.shared

    @Binding var allFilters: Filters

    @State private var selectedEventTree: Message?
    @State private var visibility: NavigationSplitViewVisibility = .all
    
    /// Process tree loaded async to avoid blocking UI
    @State private var procTree: [Message] = []
    @State private var isLoadingTree: Bool = true

    /// The primary event for this window
    private var primaryEvent: Message? {
        eventStore.getEventByID(eventID)
    }

    /// Filtered process tree (applies fork filter to cached tree)
    var filteredProcTree: [Message] {
        procTree.filter {
            userPrefs.forksAsParent || $0.es_event_type != "ES_EVENT_TYPE_NOTIFY_FORK"
        }
    }

    var body: some View {
        NavigationSplitView(columnVisibility: $visibility) {
            if selectedEventTree != nil {
                // MARK: Process tree
                List(selection: $selectedEventTree) {
                    if isLoadingTree {
                        HStack {
                            ProgressView()
                                .scaleEffect(0.7)
                            Text("Loading tree...")
                                .font(.headline)
                                .foregroundStyle(.secondary)
                        }
                    } else {
                        Text("Subtree: `\(filteredProcTree.count + 1)`")
                            .font(.headline)
                            .foregroundStyle(.secondary)
                        Divider()
                        ForEach(
                            filteredProcTree.reversed(),
                            id: \.self
                        ) { message in
                            if message.id != filteredProcTree.last?.id {
                                Label("**`\(ProcessHelpers.getTargetProcessName(message: message))`**", systemImage: "arrow.turn.down.right").contextMenu {
                                    Button("Open in new window") {
                                        openEventFacts(value: message.id)
                                    }
                                }
                                .foregroundStyle(.secondary)
                            } else {
                                Text("**`\(ProcessHelpers.getTargetProcessName(message: message))`**").contextMenu {
                                    Button("Open in new window") {
                                        openEventFacts(value: message.id)
                                    }
                                }
                                .foregroundStyle(.secondary)
                            }
                        }
                        Label("**`\(ProcessHelpers.getTargetProcessName(message: selectedEventTree!))`**", systemImage: "scope").disabled(true)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        } detail: {
            if let tree = selectedEventTree {
                SystemEventFactsView(allFilters: $allFilters, selectedMessage: tree)
                    .environmentObject(systemExtensionManager)
                    .environmentObject(userPrefs)
            } else {
                Text("No event selected")
            }
        }
        .onAppear {
            self.selectedEventTree = primaryEvent
            if selectedEventTree == nil {
                _ = NSApplication.shared.windows.filter({ $0.title.contains("Event Facts")}).map({ $0.close() })
            } else {
                loadProcTreeAsync()
            }
        }
        .onChange(of: selectedEventTree?.id) { _ in
            loadProcTreeAsync()
        }
        .toolbar {
            if let firstMessage = primaryEvent,
               let tree = selectedEventTree {
                Button(action: {
                    self.selectedEventTree = firstMessage
                }, label: {
                    Label("`\(ProcessHelpers.getTargetProcessName(message: firstMessage).prefix(14))`", systemImage: "scope")
                        .labelStyle(.titleAndIcon)
                }).disabled(selectedEventTree != nil && firstMessage.id != tree.id ? false : true)
            }
        }
        .preferredColorScheme(userPrefs.forcedDarkMode ? .dark : nil)
    }
    
    private func loadProcTreeAsync() {
        guard let event = selectedEventTree else { return }
        isLoadingTree = true
        Task {
            let tree = await systemExtensionManager.eventStore.getProcTreeAsync(for: event)
            await MainActor.run {
                self.procTree = tree
                self.isLoadingTree = false
            }
        }
    }

    init(id: UUID, allFilters: Binding<Filters>) {
        self.eventID = id
        _allFilters = allFilters
    }
}
