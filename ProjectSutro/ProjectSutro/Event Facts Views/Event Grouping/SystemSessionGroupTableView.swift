//
//  SystemSessionGroupTableView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/7/25.
//

import SwiftUI
import SutroESFramework

public enum Groups: Hashable {
    case process, session
}

struct SystemEventGroupTableViews: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Binding var allFilters: Filters
    
    @State private var selectedMessages: Set<ESMessage.ID> = []
    @State private var groupToShow: Groups?
    
    var selectedMessage: ESMessage
    var processGroup: [ESMessage]
    var sessionGroup: [ESMessage]
    
    /// Determine the default group based on availability
    private var defaultGroup: Groups {
        if !processGroup.isEmpty {
            return .process
        } else if !sessionGroup.isEmpty {
            return .session
        }
        return .process // Fallback
    }
    
    /// Check if both groups have content
    private var bothGroupsAvailable: Bool {
        !processGroup.isEmpty && !sessionGroup.isEmpty
    }
    
    /// Extract the target process name
    private var processName: String {
        if let exec = selectedMessage.event.exec {
            return exec.target.executable?.name ?? ""
        } else if let fork = selectedMessage.event.fork {
            return fork.child.executable?.name ?? ""
        }
        return selectedMessage.process.executable?.name ?? ""
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if bothGroupsAvailable {
                HStack {
                    Picker("**Select group**", selection: Binding(
                        get: { groupToShow ?? defaultGroup },
                        set: { groupToShow = $0 }
                    )) {
                        Text("Process")
                            .tag(Groups.process)
                        Text("Session")
                            .tag(Groups.session)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                }
                .padding(.bottom, 8)
                
                Divider()
                    .padding(.bottom, 8)
                
                // Show selected group
                let activeGroup = groupToShow ?? defaultGroup
                if activeGroup == .process {
                    groupView(
                        title: "Process group (\(processGroup.count))",
                        messages: processGroup
                    )
                } else {
                    groupView(
                        title: "Session group (\(sessionGroup.count))",
                        messages: sessionGroup
                    )
                }
            } else if !processGroup.isEmpty {
                groupView(
                    title: "Process group (\(processGroup.count))",
                    messages: processGroup
                )
            } else if !sessionGroup.isEmpty {
                groupView(
                    title: "Session group (\(sessionGroup.count))",
                    messages: sessionGroup
                )
            } else {
                Text("No group data available")
                    .foregroundColor(.secondary)
            }
        }
        .onAppear {
            if groupToShow == nil && bothGroupsAvailable {
                groupToShow = defaultGroup
            }
        }
        .onChange(of: processGroup.isEmpty) { _ in
            validateSelection()
        }
        .onChange(of: sessionGroup.isEmpty) { _ in
            validateSelection()
        }
    }
    
    @ViewBuilder
    private func groupView(title: String, messages: [ESMessage]) -> some View {
        VStack(alignment: .leading) {
            Text(title)
                .bold()
            
            if #available(macOS 14, *) {
                CustomizableSystemProcessExecTableView(
                    messages: messages,
                    simple: true,
                    messageSelections: $selectedMessages,
                    allFilters: $allFilters
                )
                .environmentObject(systemExtensionManager)
            } else {
                SystemProcessExecTableView(
                    messages: messages,
                    simple: true,
                    messageSelections: $selectedMessages,
                    allFilters: $allFilters
                )
                .environmentObject(systemExtensionManager)
            }
        }
    }
    
    /// Validate and update selection if current group becomes empty
    private func validateSelection() {
        guard bothGroupsAvailable else {
            groupToShow = nil
            return
        }
        
        guard let current = groupToShow else { return }
        
        switch current {
        case .process where processGroup.isEmpty:
            groupToShow = .session
        case .session where sessionGroup.isEmpty:
            groupToShow = .process
        default:
            break
        }
    }
}
