//
//  LaunchItemSystemEventViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework

struct SystemLaunchItemEventTableView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.openWindow) private var openEventJSON
    
    @EnvironmentObject var userPrefs: UserPrefs
    
    var launchItemEvents: [ESMessage]
    @Binding var eventSelection: Set<ESMessage.ID>
    
    @Binding var allFilters: Filters
    
    var body: some View {
        Section(header: Label("Background Task Management Items", systemImage: "lock.doc").font(.title2)) {
            Table(of: ESMessage.self, selection: $eventSelection) {
                TableColumn("Persistance type") { (
                    message: ESMessage
                ) in
                    Text("`\(message.event.btm_launch_item_add!.item.item_type_string)`")
                }
                TableColumn("Launch item name") { (
                    message: ESMessage
                ) in
                    Text("`\(URL(fileURLWithPath: message.event.btm_launch_item_add!.item.item_path).lastPathComponent)`")
                }
                TableColumn("Launch item path") { (
                    message: ESMessage
                ) in
                    Text("`(event.btm_launch_item_add_event!.file_path!)`")
                }
                TableColumn("Is legacy?") { (
                    message: ESMessage
                ) in
                    Text("`\(message.event.btm_launch_item_add!.item.legacy ? "Yes" : "No")`")
                }
            } rows: {
                ForEach(launchItemEvents) { (
                    message: ESMessage
                ) in
                    TableRow(message).contextMenu {
                        if message.event.exec != nil {
                            TableExecEventContextMenu(allFilters: $allFilters, message: message)
                                .environmentObject(systemExtensionManager)
                                .environmentObject(userPrefs)
                        } else {
                            TableNonExecContextMenus(allFilters: $allFilters, message: message)
                                .environmentObject(systemExtensionManager)
                                .environmentObject(userPrefs)
                        }
                    }
                  }
            }
        }
    }
}
