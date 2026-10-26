//
//  AgentSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/30/22.
//

import SwiftUI
import SutroESFramework
import Foundation


class UserPrefs: ObservableObject {
    // MARK: - Context menus
    // @note these are for non-process execution events
    @AppStorage("contextInitiatingEUIDFilter") var contextInitiatingEUIDFilter = true  // Enable filtering by `initiating_euid_human`
    @AppStorage("contextInitiatingPathFilter") var contextInitiatingPathFilter: Bool = true  // Enable filtering by `initiating_process_path`
    @AppStorage("contextTargetPathFilter") var contextTargetPathFilter: Bool = false  // Enable filtering by `target_path`
    @AppStorage("contextInitiatingPathMute") var contextInitiatingPathMute: Bool = true  // Enable muting by `initiating_process_path`
    @AppStorage("contextTargetPathMute") var contextTargetPathMute: Bool = false  // Enable muting by `target_path`
    @AppStorage("contextEventUnsubscribe") var contextEventUnsubscribe: Bool = true  // Enable event unsubscription by `es_event_type`
    
    // @note these are for the process execution events
    @AppStorage("contextExecInitiatingEUIDFilter") var contextExecInitiatingEUIDFilter = true  // EXEC: Enable filtering by `initiating_euid_human`
    @AppStorage("contextExecInitiatingPathFilter") var contextExecInitiatingPathFilter: Bool = false  // EXEC: Enable filtering by `initiating_process_path`
    @AppStorage("contextExecTargetPathFilter") var contextExecTargetPathFilter: Bool = true  // EXEC: Enable filtering by `target_path`
    @AppStorage("contextExecInitiatingPathMute") var contextExecInitiatingPathMute: Bool = false  // EXEC: Enable muting by `initiating_process_path`
    @AppStorage("contextExecTargetPathMute") var contextExecTargetPathMute: Bool = true  // EXEC: Enable muting by `target_path`
    @AppStorage("contextExecEventUnsubscribe") var contextExecEventUnsubscribe: Bool = true  // EXEC: Enable event unsubscription by `es_event_type`
    
    
    // MARK: - App lifecycle and state management
    @AppStorage("lifecycleAutoUpdate") var autoUpdates = true // When the app first launches it'll check for updates
    @AppStorage("lifecycleWarnBeforeQuit") var lifecycleWarnBeforeQuit = true  // Warn the user before quitting the app
    @AppStorage("lifecycleWarnBeforeClear") var lifecycleWarnBeforeClear = true  // Warn the user before clearing events
    
    // MARK: - Process tree
    // Which parents Event Facts' process tree follows is kept under ProcessLineageMode.storageKey: the View menu,
    // Settings and the tree each read it through their own @AppStorage, so each follows the others' changes.
    
    // MARK: - Dark mode
    @AppStorage("forcedDarkMode") var forcedDarkMode: Bool = false
    
    
    /// Put both event tables' context menus back as Mac Monitor ships them: Settings ▸ Context Menus' Reset.
    public func resetContextPreferences() {
        contextInitiatingEUIDFilter = true
        contextInitiatingPathFilter = true
        contextTargetPathFilter = false
        contextInitiatingPathMute = true
        contextTargetPathMute = false
        contextEventUnsubscribe = true
        contextExecInitiatingEUIDFilter = true
        contextExecInitiatingPathFilter = false
        contextExecTargetPathFilter = true
        contextExecInitiatingPathMute = false
        contextExecTargetPathMute = true
        contextExecEventUnsubscribe = true
    }

    /// Reset the context menus, and warn again before quitting and clearing: Settings ▸ General's Reset.
    public func resetAllPreferences() {
        resetContextPreferences()
        lifecycleWarnBeforeQuit = true
        lifecycleWarnBeforeClear = true
    }
}


// MARK: - Force dark mode
/// Force dark mode, for every window at once. A window's `preferredColorScheme` only takes when the window opens, so
/// switching it in Settings changed only windows opened afterwards. The app's appearance changes them all.
enum ForcedDarkMode {
    /// Where the preference is kept.
    static let key = "forcedDarkMode"
    /// Watches the preference, once it's being followed.
    private static var observer: NSObjectProtocol?

    /// Apply the preference now, and again whenever it changes, from Settings or the app menu.
    static func follow() {
        apply()
        guard observer == nil else { return }
        observer = NotificationCenter.default.addObserver(forName: UserDefaults.didChangeNotification, object: nil,
                                                          queue: .main) { _ in apply() }
    }

    /// Dark when the preference is on, and otherwise whatever the system is.
    private static func apply() {
        let name: NSAppearance.Name? = UserDefaults.standard.bool(forKey: key) ? .darkAqua : nil
        guard NSApp.appearance?.name != name else { return }
        NSApp.appearance = name.flatMap { NSAppearance(named: $0) }
    }
}


// MARK: - Settings window
/// Mac Monitor's Settings, laid out as System Settings: a full-height sidebar with its search field and the Security
/// Extension's status card above the panes, and the pane's name in the toolbar beside Back and Forward.
struct AgentSettingsView: View {
    @Binding var allFilters: Filters
    @Binding var eventMaskEnabled: Bool

    /// The pane showing: General whenever Settings opens.
    @State private var selection: SettingsPane = .general
    /// What's typed in the sidebar's search field.
    @State private var query = ""
    /// The panes Back and Forward return to, most recent last.
    @State private var history = (back: [SettingsPane](), forward: [SettingsPane]())

    var body: some View {
        NavigationSplitView {
            List(selection: Binding(get: { selection }, set: { $0.map(show) })) {
                if SettingsPane.securityExtension.matches(query) {
                    SettingsStatusCard().tag(SettingsPane.securityExtension)
                }
                ForEach(SettingsPane.groups.indices, id: \.self) { index in
                    let panes = SettingsPane.groups[index].filter { $0.matches(query) }
                    if !panes.isEmpty {
                        Section {
                            ForEach(panes) { pane in
                                Label { Text(pane.title) } icon: { SettingsIconTile(pane: pane) }.tag(pane)
                            }
                        }
                    }
                }
            }
            .listStyle(.sidebar)
            /// The minimum as well: with the sidebar button removed, SwiftUI otherwise opens the sidebar at 144 points
            /// on first launch and saves that width.
            .frame(minWidth: 240)
            .navigationSplitViewColumnWidth(240)
            .modifier(NoSidebarToggle())
        } detail: {
            pane(selection)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .navigationTitle(selection.title)
                .toolbar {
                    ToolbarItem(placement: .navigation) {
                        ControlGroup {
                            Button(action: goBack) { Label("Back", systemImage: "chevron.left") }
                                .disabled(history.back.isEmpty)
                                .keyboardShortcut("[", modifiers: .command)
                                .help("Back")
                            Button(action: goForward) { Label("Forward", systemImage: "chevron.right") }
                                .disabled(history.forward.isEmpty)
                                .keyboardShortcut("]", modifiers: .command)
                                .help("Forward")
                        }
                        .controlGroupStyle(.navigation)
                    }
                }
        }
        .searchable(text: $query, placement: .sidebar, prompt: "Search")
        /// The window can keep its view when it closes, so start over at General each time it opens.
        .onAppear {
            selection = .general
            history = ([], [])
        }
        .frame(minWidth: 820, idealWidth: 1000, maxWidth: .infinity, minHeight: 560, idealHeight: 720,
               maxHeight: .infinity)
    }

    /// Show a pane, remembering the one it replaces for Back.
    ///
    /// - Parameter pane: The pane.
    private func show(_ pane: SettingsPane) {
        guard pane != selection else { return }
        history.back.append(selection)
        history.forward.removeAll()
        selection = pane
    }

    /// Return to the pane shown before this one.
    private func goBack() {
        guard let pane = history.back.popLast() else { return }
        history.forward.append(selection)
        selection = pane
    }

    /// Return to the pane Back left.
    private func goForward() {
        guard let pane = history.forward.popLast() else { return }
        history.back.append(selection)
        selection = pane
    }

    /// A pane's view.
    ///
    /// - Parameter pane: The pane.
    /// - Returns: Its view.
    @ViewBuilder
    private func pane(_ pane: SettingsPane) -> some View {
        switch pane {
        case .securityExtension: SecurityExtensionSettingsView()
        case .general: GeneralSettingsView()
        case .systemDetails: SystemDetailsSettingsView()
        case .subscriptions: SubscriptionsSettingsView(allFilters: $allFilters, eventMaskEnabled: $eventMaskEnabled)
        case .pathMuting: PathMutingSettingsView()
        case .findings: FindingsSettingsView()
        case .commandLine: SettingsPage(pane: pane) { CommandLineToolSettingsView() }
        case .telemetrySchema: TelemetrySchemaSettingsView()
        case .eventTables: ContextMenuSettingsView()
        }
    }
}


/// System Settings' sidebar can't be hidden, so neither can this one: no sidebar button in the toolbar (macOS 14+).
private struct NoSidebarToggle: ViewModifier {
    func body(content: Content) -> some View {
        if #available(macOS 14, *) {
            content.toolbar(removing: .sidebarToggle)
        } else {
            content
        }
    }
}
