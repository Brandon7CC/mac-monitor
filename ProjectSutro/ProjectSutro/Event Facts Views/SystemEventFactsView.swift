//
//  SystemEventFactsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework


struct SystemEventDetailsView: View {
    var selectedMessage: ESMessage
    
    var body: some View {
        List {
            SystemTargetProcessView(selectedMessage: selectedMessage)
        }
    }
}


// MARK: - Event Facts tab view
/// An event's facts, a tab at a time. The tabs sit centered in the window's title bar, leaving the window's height to
/// the facts, whenever they fit there. When the window is too narrow, they move to the top of the facts instead: macOS
/// would otherwise hide them in the toolbar's overflow menu.
struct SystemEventFactsView : View {
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
        CoreDataController.shared.getProcGroup(message: selectedMessage)
    }
    private var procSessionGroup: [ESMessage] {
        CoreDataController.shared.getProcSessionGroup(message: selectedMessage)
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
            /// EXEC only. The enrichment view describes the exec target,
            /// and FORK events can have correlated events too.
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
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { width = $0 }
        /// Only the newest: below macOS 26.4 a task hops to the main actor, so an older one can arrive after it.
        .task(id: shown == .correlation) { if !Task.isCancelled { showsCorrelation = shown == .correlation } }
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
        case .groups:
            SystemEventGroupTableViews(allFilters: $allFilters, selectedMessage: selectedMessage,
                                       processGroup: procGroup, sessionGroup: procSessionGroup)
        case .parent:
            SystemInitiatingProcessView(selectedMessage: selectedMessage)
                .textSelection(.enabled)
        case .json:
            SystemEventJSONView(selectedMessage: selectedMessage)
        }
    }
}


struct AppWrapperForFacts: View {
    @FetchRequest var coreDataEvents: FetchedResults<ESMessage>
    
    
    @Binding var allFilters: Filters
    
    @State private var selectedEventTree: ESMessage?
    /// Is the Correlation tab showing?
    @State private var showsCorrelation = false
    @State private var visibility: NavigationSplitViewVisibility = .all
    /// Is the event gone, so the window should close?
    @State private var isGone = false
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationSplitView(columnVisibility: $visibility) {
            // MARK: Process tree
            ProcessLineageSidebar(selection: $selectedEventTree)
        } detail: {
            if let tree = selectedEventTree {
                SystemEventFactsView(allFilters: $allFilters, selectedMessage: tree,
                                     showsCorrelation: $showsCorrelation)
            } else {
                Text("No event selected")
            }
        }
        /// An event that's gone closes its window. On macOS 13 `dismiss()` may not close a WindowGroup's window, so
        /// ``WindowCloser`` closes it too.
        .onAppear {
            selectedEventTree = coreDataEvents.first
            guard selectedEventTree == nil else { return }
            isGone = true
            dismiss()
        }
        .background(WindowCloser(isClosing: isGone))
        /// Clear deletes the events (and processes) this window shows, or takes their store away: let go of them first,
        /// the fetch too, which would otherwise keep an event whose store is gone and raise when it's next read.
        .onReceive(NotificationCenter.default.publisher(for: CoreDataController.eventsWillClear)) { _ in
            selectedEventTree = nil
            coreDataEvents.nsPredicate = NSPredicate(value: false)
        }
        .toolbar {
            /// The selection first: after a Clear there's none, and the fetch isn't read.
            if let tree = selectedEventTree,
               let firstMessage = coreDataEvents.first {
                ToolbarItem(placement: .navigation) {
                    Button { selectedEventTree = firstMessage } label: {
                        Label("`\(ProcessHelpers.getTargetProcessName(message: firstMessage).prefix(14))`",
                              systemImage: "scope")
                            .labelStyle(.titleAndIcon)
                    }.disabled(firstMessage.id == tree.id)
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
            let json = events.map { ProcessHelpers.eventToJSON(value: $0, pretty: true) }.joined(separator: "\n")
            return [NSItemProvider(object: json as NSString)]
        }
    }
    
    
    init(id: UUID, allFilters: Binding<Filters>) {
        _coreDataEvents = FetchRequest<ESMessage>(sortDescriptors: [], predicate: NSPredicate(format: "id == %@", id as CVarArg))
        _allFilters = allFilters
    }
}


/// Closes the window it's in once ``isClosing`` is true, as soon as it's in one.
private struct WindowCloser: NSViewRepresentable {
    let isClosing: Bool

    func makeNSView(context: Context) -> CloserView { CloserView() }

    func updateNSView(_ view: CloserView, context: Context) {
        view.isClosing = isClosing
        view.closeIfAsked()
    }

    final class CloserView: NSView {
        var isClosing = false

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            closeIfAsked()
        }

        /// Close the window after this update. Closing one `dismiss()` already closed does nothing.
        func closeIfAsked() {
            guard isClosing, let window else { return }
            DispatchQueue.main.async { [weak window] in window?.close() }
        }
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
