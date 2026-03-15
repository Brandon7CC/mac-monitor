//
//  TableExecEventContextMenu.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 5/22/23.
//

import SwiftUI
import SutroESFramework
import OSLog


// MARK: Process execution event context menu
// @discussion: This context menu is *only* safe to use on `ES_EVENT_TYPE_NOTIFY_EXEC`
struct TableExecEventContextMenu: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.openWindow) private var openEventJSON
    
    @EnvironmentObject var userPrefs: UserPrefs

    @Binding var allFilters: Filters
    
    var message: ESMessage
    private var exec: ESProcessExecEvent {
        message.event.exec!
    }
    
    var body: some View {
        // MARK: Event metadata
        Group {
            Button(action: {
                openEventJSON(value: message.id)
            }) { Text("Event metadata") }
            
            Divider()
        }
        
        // MARK: Filter target_path
        if userPrefs.contextExecTargetPathFilter {
            if let exe = message.event.exec!.target.executable,
               !exe.path.isEmpty {
                let procPath = exe.path
                // MARK: Secodary click "Filter target process globally"
                Button(action: {
                    allFilters.targetPaths.append(procPath)
                }) {
                    HStack {
                        Text("Filter target path: \"`\(procPath)`\"")
                    }
                }
            }
        }
        
        // MARK: Filter ES event
        Button(action: {
            allFilters.events.append(message.es_event_type)
        }) {
            HStack {
                Text("Filter event: \"`\(message.es_event_type)`\"")
            }
        }
        
        // MARK: Filter EUID
        if userPrefs.contextExecInitiatingEUIDFilter {
            Button(action: {
                allFilters.userIDs.append(message.process.euid_human ?? "")
            }) {
                HStack {
                    Text(
                        "Filter euid: \"`\(message.process.euid_human ?? "")`\""
                    )
                }
            }
        }
        
        // MARK: Filter initiating_process_path
        if userPrefs.contextExecInitiatingPathFilter {
            if let exe = message.process.executable,
            !exe.path.isEmpty {
                let procPath = exe.path
                Button(action: {
                    os_log("Filtering from view: \(message.id) --> \(procPath)")
                    //Filter this path from view
                    allFilters.initiatingPaths.append(procPath)
                }) {
                    HStack {
                        Text(
                            "Filter initiating path: \"`\(procPath)`\""
                        )
                    }
                }
            }
            
        }
        
        Divider()
        // MARK: - Select Process
        
        Text("**Select**")
        if let tgtProcName = exec.target.executable?.name,
           let tgtProcPath = exec.target.executable?.path {
            Button(action: {
                allFilters.rootIncludedTargetProcessPath = tgtProcPath
                allFilters.shouldIncludeProcessSubTrees = false
            }) {
                HStack {
                    Text(
                        "→ Only: \"`\(tgtProcName)`\" events"
                    )
                }
            }
            
            Button(action: {
                allFilters.rootIncludedTargetProcessPath = tgtProcPath
                allFilters.shouldIncludeProcessSubTrees = true
            }) {
                HStack {
                    Text(
                        "↕ Full tree: \"`\(tgtProcName)`\" events"
                    )
                }
            }
        }
        
        
        Divider()
        
        // MARK: Advanced context menu
        Text("**Advanced**")
        AdvancedExecEventContextMenu(allFilters: $allFilters, message: message)
            .environmentObject(userPrefs)
    }
}

// MARK: Advanced process execution context menu
struct AdvancedExecEventContextMenu: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    
    @Environment(\.openWindow) private var openEventJSON
    @Binding var allFilters: Filters
    
    var message: ESMessage
    
    private var exec: ESProcessExecEvent {
        message.event.exec!
    }
    
    private var procPath: URL? {
        URL(string: exec.target.executable?.path ?? "")
    }
    
    private var procName: String {
        return procPath?.lastPathComponent ?? ""
    }
    
    var body: some View {
        // MARK: Initiating path filter
        
        
        // MARK: Target path mute
        if userPrefs.contextExecTargetPathMute {
            Button(
action: {
                os_log("Requesting ES mute the target process path for: \(message.id)\n \(procName)")
                // Mute the binaries initiating process path globally (for all events)
                systemExtensionManager
        .puntPathToMute(
            pathToMute: exec.target.executable?.path ?? "",
            muteCase:  ES_MUTE_PATH_TYPE_TARGET_LITERAL,
            pathEvents: []
        )
                systemExtensionManager.requestMutedPaths()
            }) {
                HStack {
                    Text("Mute target path: \"`\(procName)`\"")
                }
            }
        }
        
        // MARK: Initiating path mute
        if userPrefs.contextExecInitiatingPathMute {
            Button(
action: {
    os_log(
        "Requesting ES mute the initiating process path for: \(message.id)\n \(message.process.executable?.name ?? "")"
    )
                // Mute the binaries initiating process path globally (for all events)
    systemExtensionManager
        .puntPathToMute(
            pathToMute: message.process.executable?.path ?? "",
            muteCase:  ES_MUTE_PATH_TYPE_LITERAL,
            pathEvents: []
        )
                systemExtensionManager.requestMutedPaths()
            }) {
                HStack {
                    Text(
                        "Mute initiating path: \"`\(message.process.executable?.name ?? "")`\""
                    )
                }
            }
        }
        
        // MARK: Unsubscribe from event
        if userPrefs.contextExecEventUnsubscribe {
            Button(action: {
                os_log("Requesting ES unsubscribe from: \(message.es_event_type)")
                // Mute the binaries initiating process path globally (for all events)
                systemExtensionManager.puntEventToUnsubscribe(eventString: message.es_event_type)
            }) {
                HStack {
                    Text("Unsubscribe: \"`\(message.es_event_type)`\"")
                }
            }
        }
    }
}
