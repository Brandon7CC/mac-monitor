//
//  EventRowMenu.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/2/26.
//

import SwiftUI
import AppKit
import EndpointSecurity
import OSLog
import SutroESFramework


// MARK: - Row menu
/// The right-click menu of a row in the AppKit event tables.
///
/// Item for item the same as ``TableNonExecContextMenus`` and ``TableExecEventContextMenu``: the same items, titles, order,
/// and preferences. Those views are the menus of the SwiftUI tables in the Event Facts windows (correlation, enrichment,
/// and process groups), so keep the two in sync.
///
/// Everything an item needs is read when the menu is built. An item never touches the event again, which may have been
/// cleared by the time the item is chosen.
struct EventRowMenu {
    /// The right-clicked event.
    let message: ESMessage
    let prefs: UserPrefs
    let filters: Binding<Filters>
    let manager: EndpointSecurityManager
    /// Opens the "Event Facts" window for an event.
    let openWindow: OpenWindowAction
    
    /// - Returns: The menu's items: the process execution menu for `EXEC` events, the general one for everything else.
    func items() -> [NSMenuItem] {
        guard let eventType = message.es_event_type else { return [] }
        if let exec = message.event.exec { return execItems(exec, eventType) }
        return nonExecItems(eventType)
    }
    
    // MARK: Non-exec
    /// ``TableNonExecContextMenus`` and ``AdvancedNonExecContextMenu``.
    ///
    /// - Parameter eventType: The event's `ES_EVENT_TYPE_*` name.
    /// - Returns: The menu's items.
    private func nonExecItems(_ eventType: String) -> [NSMenuItem] {
        let filters = filters, manager = manager
        let path = message.process.executable?.path
        let name = message.process.executable?.name
        let euid = message.process.euid_human ?? ""
        let targetPath = message.target_path ?? ""
        
        var items = [eventMetadata(), .separator()]
        if prefs.contextInitiatingPathFilter {
            items.append(Self.item("Filter initiating path: \"\(name ?? "")\"") { filters.wrappedValue.initiatingPaths.append(path ?? "") })
        }
        items.append(filterEvent(eventType))
        if prefs.contextInitiatingEUIDFilter {
            items.append(Self.item("Filter euid: \"\(euid)\"") { filters.wrappedValue.userIDs.append(euid) })
        }
        
        items += [.separator(), Self.header("Select")]
        if let name, let path {
            items.append(Self.item("→ Only: \"\(name)\" events") { filters.wrappedValue.rootIncludedInitiatingProcessPath = path })
            items.append(Self.item("↕ Full tree: \"\(name)\" events") {
                filters.wrappedValue.rootIncludedInitiatingProcessPath = path
                filters.wrappedValue.shouldIncludeProcessSubTrees = true
            })
        }
        
        items += [.separator(), Self.header("Advanced")]
        /// File and `MMAP` events filter and mute the directory they target rather than the file.
        let byDirectory = !targetPath.isEmpty && IntelligentEventTargeting.targetShouldBeParentDir(esEventType: eventType)
        let directory = URL(fileURLWithPath: targetPath).deletingLastPathComponent().path
        if prefs.contextTargetPathFilter && !targetPath.isEmpty {
            let filtered = byDirectory ? directory : targetPath
            items.append(Self.item("Filter target path: \"\(filtered)/\"") { filters.wrappedValue.targetPaths.append(filtered) })
        }
        if prefs.contextInitiatingPathMute {
            items.append(Self.item("Mute initiating path: \"\(path ?? "")\"") {
                manager.puntPathToMute(pathToMute: path ?? "", muteCase: ES_MUTE_PATH_TYPE_LITERAL, pathEvents: [])
                manager.requestMutedPaths()
            })
        }
        if prefs.contextTargetPathMute && !targetPath.isEmpty {
            if byDirectory {
                items.append(Self.item("Mute target path event: \"\(directory)/\"") {
                    manager.puntPathToMute(pathToMute: directory, muteCase: ES_MUTE_PATH_TYPE_TARGET_PREFIX, pathEvents: [eventType])
                    manager.requestMutedPaths()
                })
            } else {
                items.append(Self.item("Mute target path event: \"\(targetPath)/\"") {
                    manager.puntPathToMute(pathToMute: targetPath, muteCase: ES_MUTE_PATH_TYPE_TARGET_LITERAL, pathEvents: [eventType])
                    manager.requestMutedPaths()
                })
            }
        }
        if prefs.contextEventUnsubscribe {
            items.append(unsubscribe(eventType))
        }
        return items
    }
    
    // MARK: Exec
    /// ``TableExecEventContextMenu`` and ``AdvancedExecEventContextMenu``.
    ///
    /// - Parameters:
    ///   - exec: The event's process execution.
    ///   - eventType: The event's `ES_EVENT_TYPE_*` name.
    /// - Returns: The menu's items.
    private func execItems(_ exec: ESProcessExecEvent, _ eventType: String) -> [NSMenuItem] {
        let filters = filters, manager = manager, id = message.id
        let targetPath = exec.target.executable?.path
        let targetName = exec.target.executable?.name
        /// The SwiftUI menu names the muted target by the last component of `URL(string:)`, not the executable's name.
        let targetFileName = URL(string: targetPath ?? "")?.lastPathComponent ?? ""
        let path = message.process.executable?.path
        let name = message.process.executable?.name
        let euid = message.process.euid_human ?? ""
        
        var items = [eventMetadata(), .separator()]
        if prefs.contextExecTargetPathFilter, let targetPath {
            items.append(Self.item("Filter target path: \"\(targetPath)\"") { filters.wrappedValue.targetPaths.append(targetPath) })
        }
        items.append(filterEvent(eventType))
        if prefs.contextExecInitiatingEUIDFilter {
            items.append(Self.item("Filter euid: \"\(euid)\"") { filters.wrappedValue.userIDs.append(euid) })
        }
        if prefs.contextExecInitiatingPathFilter, let path {
            items.append(Self.item("Filter initiating path: \"\(path)\"") {
                os_log("Filtering from view: \(id) --> \(path)")
                filters.wrappedValue.initiatingPaths.append(path)
            })
        }
        
        items += [.separator(), Self.header("Select")]
        if let targetName, let targetPath {
            items.append(Self.item("→ Only: \"\(targetName)\" events") {
                filters.wrappedValue.rootIncludedTargetProcessPath = targetPath
                filters.wrappedValue.shouldIncludeProcessSubTrees = false
            })
            items.append(Self.item("↕ Full tree: \"\(targetName)\" events") {
                filters.wrappedValue.rootIncludedTargetProcessPath = targetPath
                filters.wrappedValue.shouldIncludeProcessSubTrees = true
            })
        }
        
        items += [.separator(), Self.header("Advanced")]
        if prefs.contextExecTargetPathMute {
            items.append(Self.item("Mute target path: \"\(targetFileName)\"") {
                os_log("Requesting ES mute the target process path for: \(id)\n \(targetFileName)")
                manager.puntPathToMute(pathToMute: targetPath ?? "", muteCase: ES_MUTE_PATH_TYPE_TARGET_LITERAL, pathEvents: [])
                manager.requestMutedPaths()
            })
        }
        if prefs.contextExecInitiatingPathMute {
            items.append(Self.item("Mute initiating path: \"\(name ?? "")\"") {
                os_log("Requesting ES mute the initiating process path for: \(id)\n \(name ?? "")")
                manager.puntPathToMute(pathToMute: path ?? "", muteCase: ES_MUTE_PATH_TYPE_LITERAL, pathEvents: [])
                manager.requestMutedPaths()
            })
        }
        if prefs.contextExecEventUnsubscribe {
            items.append(unsubscribe(eventType))
        }
        return items
    }
    
    // MARK: Shared items
    /// "Event metadata": open the event in an "Event Facts" window.
    ///
    /// - Returns: The menu item.
    private func eventMetadata() -> NSMenuItem {
        let openWindow = openWindow, id = message.id
        return Self.item("Event metadata") { openWindow(value: id) }
    }
    
    /// "Filter event": hide every event of this type.
    ///
    /// - Parameter eventType: The `ES_EVENT_TYPE_*` name to hide.
    /// - Returns: The menu item.
    private func filterEvent(_ eventType: String) -> NSMenuItem {
        let filters = filters
        return Self.item("Filter event: \"\(eventType)\"") { filters.wrappedValue.events.append(eventType) }
    }
    
    /// "Unsubscribe": stop Endpoint Security delivering this event type.
    ///
    /// - Parameter eventType: The `ES_EVENT_TYPE_*` name to unsubscribe from.
    /// - Returns: The menu item.
    private func unsubscribe(_ eventType: String) -> NSMenuItem {
        let manager = manager
        return Self.item("Unsubscribe: \"\(eventType)\"") {
            os_log("Requesting ES unsubscribe from: \(eventType)")
            manager.puntEventToUnsubscribe(eventString: eventType)
        }
    }
    
    // MARK: Items
    /// A menu item that runs `action`.
    ///
    /// Titles are plain text: SwiftUI shows its menus' Markdown (code spans, bold) as plain titles too.
    ///
    /// - Parameters:
    ///   - title: The item's title.
    ///   - action: Runs when the item is chosen.
    /// - Returns: The menu item.
    private static func item(_ title: String, action: @escaping () -> Void) -> NSMenuItem {
        ActionMenuItem(title: title, action: action)
    }
    
    /// A disabled section title ("Select", "Advanced").
    ///
    /// - Parameter title: The section's name.
    /// - Returns: The menu item.
    private static func header(_ title: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.isEnabled = false
        return item
    }
}


// MARK: - Action menu item
/// A menu item that runs a closure.
private final class ActionMenuItem: NSMenuItem {
    private let handler: () -> Void
    
    /// - Parameters:
    ///   - title: The item's title.
    ///   - action: Runs when the item is chosen.
    init(title: String, action: @escaping () -> Void) {
        handler = action
        super.init(title: title, action: #selector(run), keyEquivalent: "")
        target = self
    }
    
    required init(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    
    @objc private func run() { handler() }
}
