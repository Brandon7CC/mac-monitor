//
//  ProcessLineageSidebar.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Process tree sidebar
/// Event Facts' sidebar: the selected event's process tree, by Unix parents or by launched-by parents, as chosen in
/// the View menu or in Settings > User Preferences (``ProcessLineageMode``). It follows a change at once, and its
/// header names the choice. Choosing a row shows that event.
struct ProcessLineageSidebar: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    @Environment(\.openWindow) private var openEventFacts
    /// Which parents the tree follows.
    @AppStorage(ProcessLineageMode.storageKey) private var mode = ProcessLineageMode.defaultMode
    
    /// The event Event Facts shows.
    @Binding var selection: ESMessage?
    
    var body: some View {
        if let selected = selection {
            switch mode {
            case .unix: unixTree(of: selected)
            case .launchedByParent: launchedByParentTree(of: selected)
            }
        }
    }
    
    /// The tree's first row: how many processes it shows, and under that which parents it follows, so the tree says
    /// which it is when the View menu or Settings changes it. VoiceOver reads the two as one element; the tooltip
    /// says where to change it.
    ///
    /// - Parameter count: The processes the tree shows, the selected event's included.
    /// - Returns: The row.
    private func subtreeHeader(count: Int) -> some View {
        VStack(alignment: .leading) {
            Text("Subtree: `\(count)`")
                .font(.headline)
            Text(mode.title)
                .font(.subheadline)
        }
        .foregroundStyle(.secondary)
        .accessibilityElement(children: .combine)
        .help("\(mode.explanation) Change it in the View menu or in Settings > User Preferences.")
    }
    
    
    // MARK: Unix parents
    /// The selected event's ancestors, nearest first (forks only if they count as parents).
    ///
    /// - Parameter event: The selected event.
    /// - Returns: Its process tree, looked up in the store.
    private func procTree(for event: ESMessage) -> [ESMessage] {
        systemExtensionManager.coreDataContainer.getProcTree(targetEvent: event).filter({
            /// Forks as parent
            if userPrefs.forksAsParent {
                true
            } else {
                $0.es_event_type != "ES_EVENT_TYPE_NOTIFY_FORK"
            }
        })
    }
    
    /// The process tree by Unix parents.
    ///
    /// - Parameter selected: The selected event.
    /// - Returns: Its ancestors from the farthest, then the event.
    private func unixTree(of selected: ESMessage) -> some View {
        /// One lookup per update: the tree is read for every row below.
        let tree = procTree(for: selected)
        // MARK: Process tree
        return List(selection: $selection) {
            subtreeHeader(count: tree.count + 1)
            Divider()
            ForEach(
                tree.reversed(),
                id: \.self
            ) { message in
                if message.id != tree.last?.id {
                    Label("**`\(ProcessHelpers.getTargetProcessName(message: message))`**",
                          systemImage: "arrow.turn.down.right").contextMenu {
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
            Label("**`\(ProcessHelpers.getTargetProcessName(message: selected))`**", systemImage: "scope")
                .disabled(true)
                .foregroundStyle(.secondary)
        }
    }
    
    
    // MARK: Launched-by parents
    /// The process tree by launched-by parents. Each parent's row has the symbol of the source that names it the
    /// launched-by parent of the row below, and gives VoiceOver the source's name. A parent the trace doesn't have is a
    /// dimmed row that can't be chosen.
    ///
    /// - Parameter selected: The selected event.
    /// - Returns: Its process's launched-by parents from the farthest; for an event that didn't create a process, the
    ///   process that caused it, as in the Unix tree; then the event.
    private func launchedByParentTree(of selected: ESMessage) -> some View {
        let container = systemExtensionManager.coreDataContainer
        /// One lookup per update.
        let steps = container.launchedByParents(of: selected)
        let origin = selected.createsProcess ? nil : container.findParentProc(message: selected)
        return List(selection: $selection) {
            subtreeHeader(count: steps.count + (origin == nil ? 1 : 2))
            Divider()
            ForEach(Array(steps.enumerated().reversed()), id: \.offset) { _, step in
                launchedByParentRow(step)
            }
            if let origin {
                eventRow(origin, systemImage: "arrow.turn.down.right", relation: "Caused this event",
                         help: "The process that caused this event")
            }
            Label("**`\(ProcessHelpers.getTargetProcessName(message: selected))`**", systemImage: "scope")
                .disabled(true)
                .foregroundStyle(.secondary)
        }
    }
    
    /// A launched-by parent's row: its event when the trace has it, else what the answer says about it.
    ///
    /// - Parameter step: The step.
    /// - Returns: The row.
    @ViewBuilder
    private func launchedByParentRow(_ step: LaunchedByParentStep) -> some View {
        let answer = step.launchedByParent
        let source = answer.source
        let job = answer.launchd_job.map { " The process below runs as the launchd job \($0.label)." } ?? ""
        let help = "Launched by parent of the process below (\(source.title)).\(job)"
        if let event = step.event {
            eventRow(event, systemImage: source.symbolName, relation: source.title, help: help)
        } else {
            let isLaunchd = answer.isLaunchd
            let process = answer.pid.map { " It's pid \($0)\(step.path.map { " at \($0)" } ?? "")." } ?? ""
            Label(missingTitle(step), systemImage: source.symbolName)
                .disabled(true)
                .foregroundStyle(isLaunchd ? HierarchicalShapeStyle.secondary : .tertiary)
                .help(isLaunchd ? help : "\(help)\(process) Its exec isn't in this trace.")
                .accessibilityValue(Text(isLaunchd ? source.title : "\(source.title), not in this trace"))
        }
    }
    
    /// A row for an event, which can be chosen or opened in a new window.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - systemImage: The row's symbol.
    ///   - relation: How the row relates to the row below, for VoiceOver: the symbol only shows it.
    ///   - help: The row's tooltip.
    /// - Returns: The row.
    private func eventRow(_ event: ESMessage, systemImage: String, relation: String, help: String) -> some View {
        Label("**`\(ProcessHelpers.getTargetProcessName(message: event))`**", systemImage: systemImage)
            .contextMenu {
                Button("Open in new window") {
                    openEventFacts(value: event.id)
                }
            }
            .foregroundStyle(.secondary)
            .help(help)
            .accessibilityValue(Text(relation))
            .tag(event)
    }
    
    /// The title for a launched-by parent that isn't in the trace.
    ///
    /// We show launchd with its job's label, or the parent's process name like the other rows. The pid and path are
    /// in the tooltip.
    ///
    /// - Parameter step: The step.
    /// - Returns: The row's title (Markdown).
    private func missingTitle(_ step: LaunchedByParentStep) -> LocalizedStringKey {
        let answer = step.launchedByParent
        if answer.isLaunchd {
            guard let label = answer.launchd_job?.label else { return "**`launchd`**" }
            return "**`launchd`** · `\(label)`"
        }
        guard let pid = answer.pid else { return "Launch Services · no launcher recorded" }
        guard let name = step.path.map({ ($0 as NSString).lastPathComponent }), !name.isEmpty else {
            return "pid `\(String(pid))`"
        }
        return "**`\(name)`**"
    }
}
