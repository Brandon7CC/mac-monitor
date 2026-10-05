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
    @AppStorage("forksAsParent") var forksAsParent = false
    // Which parents Event Facts' process tree follows is kept under ProcessLineageMode.storageKey: the View menu,
    // Settings and the tree each read it through their own @AppStorage, so each follows the others' changes.
    
    // MARK: - Dark mode
    @AppStorage("forcedDarkMode") var forcedDarkMode: Bool = false
    
    
    // @note reset the user preferences for non-process execution events
    public func resetNonExecPreferences() {
        contextInitiatingEUIDFilter = true
        contextInitiatingPathFilter = true
        contextTargetPathFilter = false
        contextInitiatingPathMute = true
        contextTargetPathMute = false
        contextEventUnsubscribe = true
    }

    // @note reset the user preferences for process execution events
    public func resetExecPreferences() {
        contextExecInitiatingEUIDFilter = true
        contextExecInitiatingPathFilter = false
        contextExecTargetPathFilter = true
        contextExecInitiatingPathMute = false
        contextExecTargetPathMute = true
        contextExecEventUnsubscribe = true
    }

    public func resetContextPreferences() {
        resetNonExecPreferences()
        resetExecPreferences()
    }
    
    public func resetLifecyclePreferences() {
        lifecycleWarnBeforeQuit = true
        lifecycleWarnBeforeClear = true
    }
    
    public func resetAllPreferences() {
        // Reset the context menu preferences
        resetContextPreferences()
        
        // Reset the life cycle preferences
        resetLifecyclePreferences()
    }
}


struct AgentSettingsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    @Binding var pathToMute: String
    @Binding var allFilters: Filters
    @Binding var eventMaskEnabled: Bool
    
    private enum Tabs: Hashable {
        case esMuting, esEventSubscriptions, advanced, streamTelemetry, userSettings
    }
    
    var body: some View {
        TabView {
            ESSubscriptionsView(allFilters: $allFilters, eventMaskEnabled: $eventMaskEnabled)
                .tabItem{
                    Label("Subscriptions", systemImage: "square.and.arrow.down.on.square")
                }.tag(Tabs.esEventSubscriptions)
            ESMutingTabView(pathToMute: $pathToMute)
                .environmentObject(systemExtensionManager)
                .tabItem{
                    Label("Path Muting", systemImage: "firewall")
                }.tag(Tabs.esMuting)
            UserSettingsView()
                .environmentObject(systemExtensionManager)
                .tabItem {
                    Label("User Preferences", systemImage: "slider.vertical.3").tag(Tabs.userSettings)
                }
            AdvancedView()
                .environmentObject(systemExtensionManager)
                .tabItem {
                    Label("Advanced", systemImage: "gearshape.2").tag(Tabs.advanced)
                }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading).padding(20).frame(width: 900, height: 700)
    }
}
