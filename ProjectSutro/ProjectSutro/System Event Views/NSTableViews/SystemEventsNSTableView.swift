//
//  SystemEventsNSTableView.swift
//  ProjectSutro
//
//  SwiftUI wrappers for NSTableView-based system event tables.
//

import SwiftUI
import SutroESFramework
import AppKit

struct UnifiedSystemEventsNSTableView: NSViewControllerRepresentable {
    var messageIndices: [Int]
    @Binding var messageSelections: Set<ESMessage.ID>
    @Binding var allFilters: Filters
    @Binding var ascending: Bool
    
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    @Environment(\.openWindow) private var openEventJSON
    
    func makeNSViewController(context: Context) -> UnifiedSystemEventsTableController {
        let controller = UnifiedSystemEventsTableController(allFilters: $allFilters)
        controller.systemExtensionManager = systemExtensionManager
        controller.userPrefs = userPrefs
        controller.openEventJSON = { id in
            openEventJSON(value: id)
        }
        return controller
    }
    
    func updateNSViewController(_ controller: UnifiedSystemEventsTableController, context: Context) {
        controller.setMessageIndices(messageIndices)
        controller.selectedIDs = messageSelections
        
        if controller.systemExtensionManager !== systemExtensionManager {
            controller.systemExtensionManager = systemExtensionManager
        }
        if controller.userPrefs !== userPrefs {
            controller.userPrefs = userPrefs
        }
    }
}

@available(macOS 14.0, *)
struct CustomizableUnifiedSystemEventsNSTableView: NSViewControllerRepresentable {
    var messageIndices: [Int]
    @Binding var messageSelections: Set<ESMessage.ID>
    @Binding var allFilters: Filters
    @Binding var ascending: Bool
    
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    @Environment(\.openWindow) private var openEventJSON
    
    func makeNSViewController(context: Context) -> CustomizableUnifiedSystemEventsTableController {
        let controller = CustomizableUnifiedSystemEventsTableController(allFilters: $allFilters)
        controller.systemExtensionManager = systemExtensionManager
        controller.userPrefs = userPrefs
        controller.openEventJSON = { id in
            openEventJSON(value: id)
        }
        return controller
    }
    
    func updateNSViewController(_ controller: CustomizableUnifiedSystemEventsTableController, context: Context) {
        controller.setMessageIndices(messageIndices)
        controller.selectedIDs = messageSelections
        
        if controller.systemExtensionManager !== systemExtensionManager {
            controller.systemExtensionManager = systemExtensionManager
        }
        if controller.userPrefs !== userPrefs {
            controller.userPrefs = userPrefs
        }
    }
}

struct SystemProcessExecNSTableView: NSViewControllerRepresentable {
    var messageIndices: [Int]
    var simple: Bool = false
    @Binding var messageSelections: Set<ESMessage.ID>
    @Binding var allFilters: Filters
    @Binding var ascending: Bool
    
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    @Environment(\.openWindow) private var openEventJSON
    
    func makeNSViewController(context: Context) -> SystemProcessExecTableController {
        let controller = SystemProcessExecTableController(allFilters: $allFilters, simple: simple)
        controller.systemExtensionManager = systemExtensionManager
        controller.userPrefs = userPrefs
        controller.openEventJSON = { id in
            openEventJSON(value: id)
        }
        return controller
    }
    
    func updateNSViewController(_ controller: SystemProcessExecTableController, context: Context) {
        controller.setMessageIndices(messageIndices)
        controller.selectedIDs = messageSelections
        
        if controller.systemExtensionManager !== systemExtensionManager {
            controller.systemExtensionManager = systemExtensionManager
        }
        if controller.userPrefs !== userPrefs {
            controller.userPrefs = userPrefs
        }
    }
}

@available(macOS 14.0, *)
struct CustomizableSystemProcessExecNSTableView: NSViewControllerRepresentable {
    var messageIndices: [Int]
    var simple: Bool = false
    @Binding var messageSelections: Set<ESMessage.ID>
    @Binding var allFilters: Filters
    @Binding var ascending: Bool
    
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    @Environment(\.openWindow) private var openEventJSON
    
    func makeNSViewController(context: Context) -> CustomizableSystemProcessExecTableController {
        let controller = CustomizableSystemProcessExecTableController(allFilters: $allFilters, simple: simple)
        controller.systemExtensionManager = systemExtensionManager
        controller.userPrefs = userPrefs
        controller.openEventJSON = { id in
            openEventJSON(value: id)
        }
        return controller
    }
    
    func updateNSViewController(_ controller: CustomizableSystemProcessExecTableController, context: Context) {
        controller.setMessageIndices(messageIndices)
        controller.selectedIDs = messageSelections
        
        if controller.systemExtensionManager !== systemExtensionManager {
            controller.systemExtensionManager = systemExtensionManager
        }
        if controller.userPrefs !== userPrefs {
            controller.userPrefs = userPrefs
        }
    }
}
