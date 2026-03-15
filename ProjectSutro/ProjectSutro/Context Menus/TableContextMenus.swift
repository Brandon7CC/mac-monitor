//
//  TableContextMenus.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 12/16/22.
//

import SwiftUI
import SutroESFramework
import OSLog


// MARK: Non-exec Context menu
struct TableNonExecContextMenus: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.openWindow) private var openEventJSON
    
    @EnvironmentObject var userPrefs: UserPrefs
    @Binding var allFilters: Filters
    
    var message: ESMessage
    
    var body: some View {
        Group {
            // MARK: - Secondary click "Event Facts"
            // @note non-optional
            Button(action: {
                openEventJSON(value: message.id)
            }) { Text("Event metadata") }
            
            Divider()
        }
        
        // MARK: Filter initating process globally
        if userPrefs.contextInitiatingPathFilter {
            Button(action: {
                allFilters.initiatingPaths
                    .append(message.process.executable?.path ?? "")
            }) {
                HStack {
                    Text(
                        "Filter initiating path: \"`\(message.process.executable?.name ?? "")`\""
                    )
                }
            }
        }
        
        // MARK: - Filter ES event
        // @note non-optional
        Button(action: {
            allFilters.events.append(message.es_event_type)
        }) {
            HStack {
                Text("Filter event: \"`\(message.es_event_type)`\"")
            }
        }
        
        // MARK: Filter EUID
        if userPrefs.contextInitiatingEUIDFilter {
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
        
        Divider()
        // MARK: - Select Process
        
        Text("**Select**")
        if let procName = message.process.executable?.name,
           let procPath = message.process.executable?.path {
            Button(action: {
                allFilters.rootIncludedInitiatingProcessPath = procPath
            }) {
                HStack {
                    Text(
                        "→ Only: \"`\(procName)`\" events"
                    )
                }
            }
            
            Button(action: {
                allFilters.rootIncludedInitiatingProcessPath = procPath
                allFilters.shouldIncludeProcessSubTrees = true
            }) {
                HStack {
                    Text(
                        "↕ Full tree: \"`\(procName)`\" events"
                    )
                }
            }
        }
        
        
        
        
        
        Divider()
        // MARK: - Advanced
        
        Text("**Advanced**")
        AdvancedNonExecContextMenu(allFilters: $allFilters, event: message)
            .environmentObject(userPrefs)
    }
}



struct AdvancedNonExecContextMenu: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    
    @Environment(\.openWindow) private var openEventJSON
    @Binding var allFilters: Filters
    
    var event: ESMessage
    
    var body: some View {
        // MARK: Filter target path
        if userPrefs.contextTargetPathFilter && event.target_path != nil && !event.target_path!.isEmpty {
            if IntelligentEventTargeting.targetShouldBeParentDir(esEventType: event.es_event_type) {
                let targetPath: String = event.target_path ?? ""
                let parentDir = URL(fileURLWithPath: targetPath).deletingLastPathComponent().path
                Button(action: {
                    allFilters.targetPaths.append(parentDir)
                }) {
                    Text("Filter target path: \"\(parentDir)/\"")
                }
            } else {
                Button(action: {
                    allFilters.targetPaths.append(event.target_path!)
                }) {
                    Text("Filter target path: \"\(event.target_path!)/\"")
                }
            }
            
        }
        
        if userPrefs.contextInitiatingPathMute {
            Button(
action: {
                // Mute the binaries initiating process path globally (for all events)
                systemExtensionManager
        .puntPathToMute(
            pathToMute: event.process.executable?.path ?? "",
            muteCase:  ES_MUTE_PATH_TYPE_LITERAL,
            pathEvents: []
        )
                systemExtensionManager.requestMutedPaths()
            }) {
                HStack {
                    Text(
                        "Mute initiating path: \"`\(event.process.executable?.path ?? "")`\""
                    )
                }
            }
        }
        
        Group {
            if userPrefs.contextTargetPathMute && event.target_path != nil && !event.target_path!.isEmpty {
                // MARK: Target path parent dir
                if IntelligentEventTargeting.targetShouldBeParentDir(esEventType: event.es_event_type) {
                    let targetPath: String = event.target_path ?? ""
                    let parentDir = URL(fileURLWithPath: targetPath).deletingLastPathComponent().path
                    Button(action: {
                        // Mute the target path's parent directory for the specified event
                        systemExtensionManager.puntPathToMute(pathToMute: parentDir, muteCase:  ES_MUTE_PATH_TYPE_TARGET_PREFIX, pathEvents: [event.es_event_type])
                        systemExtensionManager.requestMutedPaths()
                    }) {
                        Text("Mute target path event: \"\(parentDir)/\"")
                    }
                } else {
                    Button(action: {
                        // Mute the target path's parent directory for the specified event
                        systemExtensionManager.puntPathToMute(pathToMute: event.target_path!, muteCase:  ES_MUTE_PATH_TYPE_TARGET_LITERAL, pathEvents: [event.es_event_type])
                        systemExtensionManager.requestMutedPaths()
                    }) {
                        HStack {
                            Text("Mute target path event: \"`\(event.target_path!)`/\"")
                        }
                    }
                }
            }
        }
        
        if userPrefs.contextEventUnsubscribe {
            Button(action: {
                os_log("Requesting ES unsubscribe from: \(event.es_event_type)")
                // Mute the binaries initiating process path globally (for all events)
                systemExtensionManager.puntEventToUnsubscribe(eventString: event.es_event_type)
            }) {
                HStack {
                    Text("Unsubscribe: \"`\(event.es_event_type)`\"")
                }
            }
        }
    }
}
