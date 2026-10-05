//
//  XProtectSystemEventViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/12/23.
//

import SwiftUI
import SutroESFramework


struct SystemXProtectEventTableView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.openWindow) private var openEventJSON
    
    @EnvironmentObject var userPrefs: UserPrefs
    
    var xprotectEvents: [ESMessage]
    @Binding var eventSelection: Set<ESMessage.ID>
    
    @Binding var allFilters: Filters
    
    var body: some View {
        Section(header: Label("XProtect events", systemImage: "bolt.shield").font(.title2)) {
            Table(of: ESMessage.self, selection: $eventSelection) {
                TableColumn("Type") { message in
                    if message.event.xp_malware_detected != nil {
                        Label("Malware detected", systemImage: "bolt.shield")
                    } else if message.event.xp_malware_remediated != nil {
                        Label("Malware remediated", systemImage: "checkmark.shield")
                    }
                }
                
                TableColumn("Malware ID") { message in
                    if let xp_malware_detected = message.event.xp_malware_detected {
                        Text(xp_malware_detected.malware_identifier)
                            .monospaced()
                    } else if let xp_malware_remediated = message.event.xp_malware_remediated {
                        Text(xp_malware_remediated.malware_identifier)
                            .monospaced()
                    }
                }
                
                TableColumn("Responsible path") { message in
                    if let xp_malware_detected = message.event.xp_malware_detected {
                        Text(xp_malware_detected.detected_path)
                            .monospaced()
                    } else if let xp_malware_remediated = message.event.xp_malware_remediated {
                        Text(xp_malware_remediated.remediated_path ?? "")
                            .monospaced()
                    }
                }
            } rows: {
                ForEach(xprotectEvents) { message in
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
