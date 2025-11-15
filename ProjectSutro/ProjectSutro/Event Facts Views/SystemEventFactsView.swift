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
    
    var potentialParent: ESMessage? { systemExtensionManager.coreDataContainer.findParentProc(message: selectedMessage) }
    var procTree: [ESMessage] { systemExtensionManager.coreDataContainer.getProcTree(targetEvent: selectedMessage) }
    
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
    
    /// Process groups:
    /// - `gid`
    /// - `session_id`
    private var procGroup: [ESMessage] {
        systemExtensionManager.coreDataContainer.getProcGroup(message: selectedMessage)
    }
    private var procSessionGroup: [ESMessage] {
        systemExtensionManager.coreDataContainer
            .getProcSessionGroup(message: selectedMessage)
    }
    
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
            if selectedMessage.correlated_array.count > 1 {
                VStack(alignment: .leading) {
                    SystemEnrichedEventView(allFilters: $allFilters, selectedMessage: selectedMessage)
                        .environmentObject(systemExtensionManager)
                        .environmentObject(userPrefs)
                }
                .tabItem{ Text("Correlation") }
                .tag(EventTabs.enrichment)
            }
            
            // MARK: Process Groups
            if !procSessionGroup.isEmpty || !procGroup.isEmpty {
                VStack(alignment: .leading) {
                    SystemEventGroupTableViews(
                        allFilters: $allFilters,
                        selectedMessage: selectedMessage,
                        processGroup: procGroup,
                        sessionGroup: procSessionGroup
                    )
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
        }.padding(.all)
    }
}


struct AppWrapperForFacts: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    @Environment(\.openWindow) private var openEventFacts
    @Environment(\.managedObjectContext) var moc
    @FetchRequest var coreDataEvents: FetchedResults<ESMessage>
    
    
    @Binding var allFilters: Filters
    
    @State private var selectedEventTree: ESMessage?
    @State private var visibility: NavigationSplitViewVisibility = .all
    
    var procTree: [ESMessage] {
        if selectedEventTree != nil {
            return systemExtensionManager.coreDataContainer.getProcTree(targetEvent: selectedEventTree!).filter({
                /// Forks as parent
                if userPrefs.forksAsParent {
                    true
                } else {
                    $0.es_event_type != "ES_EVENT_TYPE_NOTIFY_FORK"
                }
            })
        }
        return []
    }
    
    var body: some View {
        NavigationSplitView(columnVisibility: $visibility) {
            if selectedEventTree != nil {
                // MARK: Process tree
                List(selection: $selectedEventTree) {
                    Text("Subtree: `\(procTree.count + 1)`")
                        .font(.headline)
                        .foregroundStyle(.secondary)
                    Divider()
                    ForEach(
                        procTree.reversed(),
                        id: \.self
                    ) { message in
                        if message.id != procTree.last!.id {
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
            self.selectedEventTree = coreDataEvents.first
            if selectedEventTree == nil {
                _ = NSApplication.shared.windows.filter({ $0.title.contains("Event Facts")}).map({ $0.close() })
            }
        }.toolbar {
            if let firstMessage = coreDataEvents.first,
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
    
    
    init(id: UUID, allFilters: Binding<Filters>) {
        _coreDataEvents = FetchRequest<ESMessage>(sortDescriptors: [], predicate: NSPredicate(format: "id == %@", id as CVarArg))
        _allFilters = allFilters
    }
}
