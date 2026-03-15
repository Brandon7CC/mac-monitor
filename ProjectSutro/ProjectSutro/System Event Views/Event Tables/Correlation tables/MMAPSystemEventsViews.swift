//
//  MMAPSystemEventsViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework


func pathIsOSAComponent(filePath: String) -> Bool {
    let osaComponents: [String] = [
        "AppleScript.component",
        "JavaScript.component",
        ".osax"
    ]
    
    return osaComponents.first(where: { filePath.contains($0) }) != nil
}

struct SystemMMAPEventTableView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.openWindow) private var openEventJSON
    @EnvironmentObject var userPrefs: UserPrefs
    
    var mmapEvents: [ESMessage]
    @Binding var eventSelection: Set<ESMessage.ID>
    @Binding var allFilters: Filters
    
    var simple: Bool = false
    
    var body: some View {
        if !simple { Divider() }
        
        Section {
            VStack(alignment: .leading, spacing: 8) {
                Label("Memory", systemImage: "memorychip").font(.title2)
                if !simple { Text("**Memory map object**") }
                
                mmapEventsTable
            }
        }
    }
    
    private var mmapEventsTable: some View {
        Table(of: ESMessage.self, selection: $eventSelection) {
            TableColumn("Mapping path") { message in
                if let mmap = message.event.mmap, !mmap.source.path.isEmpty {
                    let path = mmap.source.path
                    if pathIsOSAComponent(filePath: path) {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .symbolRenderingMode(.palette)
                                .foregroundStyle(.black, .orange)
                                .help("This file is an OSA (Open Scripting Architecture) component")
                            Text("`\(path)`").lineLimit(4)
                        }
                    } else {
                        Text("`\(path)`").lineLimit(4)
                    }
                }
            }
        } rows: {
            ForEach(mmapEvents) { (message: ESMessage) in
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
