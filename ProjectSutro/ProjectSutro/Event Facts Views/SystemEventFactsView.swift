//
//  SystemEventFactsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework


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
/// An event's facts, a tab at a time. The tabs sit centered in the window's title bar, leaving the window's height to
/// the facts, whenever they fit there. When the window is too narrow, they move to the top of the facts instead: macOS
/// would otherwise hide them in the toolbar's overflow menu.
struct SystemEventFactsView : View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    
    @EnvironmentObject var userPrefs: UserPrefs
    
    
    @Binding var allFilters: Filters
    var selectedMessage: ESMessage
    /// Is the Correlation tab showing? Then ⌘C copies the event's correlated events too.
    @Binding var showsCorrelation: Bool
    
    /// The facts' tabs, in order. Only Metadata, Parent, and JSON are always there.
    private enum FactsTab: String, CaseIterable, Identifiable {
        case metadata = "Metadata", script = "Script", plist = "PLIST", correlation = "Correlation", groups = "Groups"
        case parent = "Parent", json = "JSON"
        
        var id: String { rawValue }
    }
    
    /// The tab showing. One the event doesn't have shows Metadata instead.
    @State private var tab: FactsTab = .metadata
    /// The facts' width, which decides where the tabs fit.
    @State private var width: CGFloat = 0
    
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
    
    /// The script an interpreter ran, if Mac Monitor read it.
    private var script: (path: String, content: String)? {
        guard let exec = selectedMessage.event.exec, let content = exec.script_content,
              let path = exec.resolved_script_path, !content.isEmpty else { return nil }
        return (path, content)
    }
    
    /// A launch item's property list, if Mac Monitor read it.
    private var plist: (path: String, content: String)? {
        guard let event = selectedMessage.event.btm_launch_item_add, let plist = event.item.plist_contents,
              !plist.isEmpty else { return nil }
        return (event.item.item_path, plist)
    }
    
    var body: some View {
        /// One lookup each per update (they query the store each time they're read).
        let procGroup = self.procGroup, procSessionGroup = self.procSessionGroup
        let tabs = FactsTab.allCases.filter { tab in
            switch tab {
            case .script: return script != nil
            case .plist: return plist != nil
            /// EXEC only: the enrichment view describes the exec target, and FORK events can have correlated events too.
            case .correlation: return selectedMessage.event.exec != nil && selectedMessage.correlatedCount() > 1
            case .groups: return !procSessionGroup.isEmpty || !procGroup.isEmpty
            case .metadata, .parent, .json: return true
            }
        }
        let shown = tabs.contains(tab) ? tab : .metadata
        let inTitleBar = width >= Self.titleBarWidth(tabs: tabs.count)
        VStack(alignment: .leading, spacing: 12) {
            if !inTitleBar {
                picker(tabs, shown).frame(maxWidth: .infinity)
            }
            facts(shown, procGroup: procGroup, procSessionGroup: procSessionGroup)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .padding(.all)
        .background(GeometryReader { proxy in
            Color.clear
                .onAppear { width = proxy.size.width }
                .onChange(of: proxy.size.width) { width = $0 }
        })
        .onAppear { showsCorrelation = shown == .correlation }
        .onChange(of: shown == .correlation) { showsCorrelation = $0 }
        .toolbar {
            if inTitleBar {
                ToolbarItem(placement: .principal) { picker(tabs, shown) }
            }
        }
    }
    
    /// The tabs, as a segmented control at its full width.
    ///
    /// - Parameters:
    ///   - tabs: The event's tabs.
    ///   - shown: The tab showing.
    /// - Returns: The control.
    private func picker(_ tabs: [FactsTab], _ shown: FactsTab) -> some View {
        Picker("Facts", selection: Binding { shown } set: { tab = $0 }) {
            ForEach(tabs) { Text($0.rawValue).tag($0) }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .fixedSize()
    }
    
    /// The narrowest facts the title bar holds the tabs centered over. macOS 26 gives each tab about 90 points there,
    /// and centered, they need the process button's width (up to 14 characters) clear on both sides.
    ///
    /// - Parameter tabs: How many tabs.
    /// - Returns: The width, in points.
    private static func titleBarWidth(tabs: Int) -> CGFloat {
        310 + 90 * CGFloat(tabs)
    }
    
    /// A tab's facts.
    ///
    /// - Parameters:
    ///   - tab: The tab.
    ///   - procGroup: The event's process group.
    ///   - procSessionGroup: The event's session.
    /// - Returns: Its view.
    @ViewBuilder
    private func facts(_ tab: FactsTab, procGroup: [ESMessage], procSessionGroup: [ESMessage]) -> some View {
        switch tab {
        case .metadata:
            SystemEventDetailsView(selectedMessage: selectedMessage).padding(.bottom)
        case .script:
            if let script { FileContentView(path: script.path, content: script.content) }
        case .plist:
            if let plist { FileContentView(path: plist.path, content: plist.content) }
        case .correlation:
            SystemEnrichedEventView(allFilters: $allFilters, selectedMessage: selectedMessage)
                .environmentObject(systemExtensionManager)
                .environmentObject(userPrefs)
        case .groups:
            SystemEventGroupTableViews(allFilters: $allFilters, selectedMessage: selectedMessage,
                                       processGroup: procGroup, sessionGroup: procSessionGroup)
        case .parent:
            SystemInitiatingProcessView(selectedMessage: selectedMessage)
                .environmentObject(systemExtensionManager)
                .textSelection(.enabled)
        case .json:
            SystemEventJSONView(selectedMessage: selectedMessage)
        }
    }
}


struct AppWrapperForFacts: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    @Environment(\.openWindow) private var openEventFacts
    @FetchRequest var coreDataEvents: FetchedResults<ESMessage>
    
    
    @Binding var allFilters: Filters
    
    @State private var selectedEventTree: ESMessage?
    /// Is the Correlation tab showing?
    @State private var showsCorrelation = false
    @State private var visibility: NavigationSplitViewVisibility = .all
    
    var body: some View {
        NavigationSplitView(columnVisibility: $visibility) {
            // MARK: Process tree
            ProcessLineageSidebar(selection: $selectedEventTree)
        } detail: {
            if let tree = selectedEventTree {
                SystemEventFactsView(allFilters: $allFilters, selectedMessage: tree,
                                     showsCorrelation: $showsCorrelation)
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
        }
        /// Clear deletes the events (and processes) this window shows: let go of them first.
        .onReceive(NotificationCenter.default.publisher(for: CoreDataController.eventsWillClear)) { _ in
            selectedEventTree = nil
        }
        .toolbar {
            if let firstMessage = coreDataEvents.first,
               let tree = selectedEventTree {
                ToolbarItem(placement: .navigation) {
                    Button(action: {
                        self.selectedEventTree = firstMessage
                    }, label: {
                        Label("`\(ProcessHelpers.getTargetProcessName(message: firstMessage).prefix(14))`",
                              systemImage: "scope")
                            .labelStyle(.titleAndIcon)
                    }).disabled(selectedEventTree != nil && firstMessage.id != tree.id ? false : true)
                }
            }
        }
        .modifier(NoWindowTitle())
        /// ⌘C copies the event's JSON, unless text is selected, which the text copies first. On the Correlation tab
        /// it copies the event's correlated events after it, oldest first, as Export telemetry writes them.
        .onCopyCommand {
            guard let tree = selectedEventTree else { return [] }
            let events = showsCorrelation ? [tree] + tree.correlated_array.reversed() : [tree]
            guard events.count <= EventTableView.copyLimit else {
                let alert = NSAlert()
                alert.messageText = "Too many events to copy"
                alert.informativeText = "⌘C copies up to \(EventTableView.copyLimit.formatted()) events, and this "
                    + "event and its correlated events are \(events.count.formatted())."
                alert.runModal()
                return []
            }
            let json = events.map { ProcessHelpers.eventToPrettyJSON(value: $0) }.joined(separator: "\n")
            return [NSItemProvider(object: json as NSString)]
        }
    }
    
    
    init(id: UUID, allFilters: Binding<Filters>) {
        _coreDataEvents = FetchRequest<ESMessage>(sortDescriptors: [], predicate: NSPredicate(format: "id == %@", id as CVarArg))
        _allFilters = allFilters
    }
}


/// Leaves the window's title out of its toolbar, giving the facts' tabs its room (macOS 15+). The process button
/// names the process, and the Window menu still lists the window as Event Facts.
private struct NoWindowTitle: ViewModifier {
    func body(content: Content) -> some View {
        if #available(macOS 15, *) {
            content.toolbar(removing: .title)
        } else {
            content
        }
    }
}
