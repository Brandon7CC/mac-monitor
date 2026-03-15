//
//  SystemProcessGroupTableView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 2/24/23.
//

import SwiftUI
import SutroESFramework

struct SystemProcessGroupTableView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Binding var allFilters: Filters
    
    @State private var selectedMessages: Set<ESMessage.ID> = []
    @State private var ascending: Bool = false
    
    var selectedMessage: ESMessage
    
    private var procGroup: [Message] {
        systemExtensionManager.eventStore.getProcGroup(for: selectedMessage)
    }
    
    private var processName: String {
        if let exec = selectedMessage.event.exec {
            return exec.target.executable?.name ?? ""
        } else if let fork = selectedMessage.event.fork {
            return fork.child.executable?.name ?? ""
        }
        
        return selectedMessage.process.executable?.name ?? ""
    }
    
    var body: some View {
        Form {
            VStack(alignment: .leading) {
                Section {
                    VStack(alignment: .leading) {
                        Text("**Process group (\(procGroup.count))**")
                        GroupBox {
                            VStack(alignment: .leading) {
                                HStack {
                                    Image(systemName: "info.square")
                                    Text("Process execution events in the same group as **`\(processName)`** will show in this unified table.")
                                }.frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                        if #available(macOS 14, *) {
                            CustomizableSystemProcessExecTableView(
                                messages: procGroup,
                                simple: true,
                                messageSelections: $selectedMessages,
                                allFilters: $allFilters,
                                ascending: $ascending
                            ).environmentObject(systemExtensionManager)
                        } else {
                            SystemProcessExecTableView(
                                messages: procGroup,
                                simple: true,
                                messageSelections: $selectedMessages,
                                allFilters: $allFilters,
                                ascending: $ascending
                            ).environmentObject(systemExtensionManager)
                        }
                    }
                }
            }.padding(.all)
        }
    }
}
