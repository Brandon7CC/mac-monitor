//
//  SystemEventsTableViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework
import OSLog


struct SystemEventsTableView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    
    /// The pre-filtered System Events to display in the tables
    var messagesInScope: [ESMessage]
    
    /// Pre-filtered exec events — computed on background queue to avoid O(n) filter in view body.
    var execMessagesInScope: [ESMessage]
    
    /// Should we display the "System Security Unified" table?
    @Binding var unifiedViewSelected: Bool
    
    /// Should we display the "Process Execution" table view?
    @Binding var viewExec: Bool
    
    /// Should we display the mini-chart?
    @Binding var viewMiniChart: Bool
    
    /// Should the events be sorted in ascending order?
    @Binding var ascending: Bool
    
    /// Track all filters set by the user
    @Binding var allFilters: Filters
    
    /// The currently selected events (i.e. table rows)
    @Binding var messageSelections: Set<ESMessage.ID>
    
    
    var body: some View {
        VStack {
            // Performance note: replaced Form > Section with plain VStack.
            // Form uses NSForm-style layout that measures all children on every pass —
            // extremely expensive with high-row-count Tables. VStack with manual headers
            // provides the same visual structure at a fraction of the layout cost.
            VStack(spacing: 0) {
                // TODO: Limit the number of views the user can have displayed
                if unifiedViewSelected {
                    Label("System Security Unified", systemImage: "apple.logo")
                        .font(.title2)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal)
                        .padding(.vertical, 4)

                    if viewMiniChart {
                        GeometryReader { geo in
                            HStack {
                                // Depracated the verbose feature to enable < macOS 13 to have a "customizable table view"
                                if #unavailable(macOS 14) {
                                    // Show all columns
                                    UnifiedSystemEventsTableView(
                                        allFilters: $allFilters,
                                        messagesInScope: messagesInScope,
                                        messageSelections: $messageSelections,
                                        ascending: $ascending
                                    )
                                    .frame(
                                        width: geo.size.width * (!messagesInScope.isEmpty ? 0.80 : 1.0),
                                        height: geo.size.height
                                    )
                                    .environmentObject(systemExtensionManager)
                                    .environmentObject(userPrefs)
                                } else {
                                    CustomizableUnifiedSystemEventsTableView(
                                        allFilters: $allFilters,
                                        messagesInScope: messagesInScope,
                                        messageSelections: $messageSelections,
                                        ascending: $ascending
                                    )
                                    .frame(
                                        width: geo.size.width * (!messagesInScope.isEmpty ? 0.80 : 1.0),
                                        height: geo.size.height
                                    )
                                    .environmentObject(systemExtensionManager)
                                    .environmentObject(userPrefs)
                                }
                                
                                
                                SystemChartEventView(systemEventsInScope: messagesInScope)
                                    .frame(
                                        width: geo.size.width * (!messagesInScope.isEmpty ? 0.20 : 0.0),
                                        height: geo.size.height
                                    )
                            }
                        }
                    } else {
                        // Depracated the verbose feature to enable < macOS 13 to have a "customizable table view"
                        if #unavailable(macOS 14) {
                            // Show all columns
                            UnifiedSystemEventsTableView(
                                allFilters: $allFilters,
                                messagesInScope: messagesInScope,
                                messageSelections: $messageSelections,
                                ascending: $ascending
                            )
                            .environmentObject(systemExtensionManager)
                            .environmentObject(userPrefs)
                        } else {
                            // MARK: macOS 14+
                            CustomizableUnifiedSystemEventsTableView(
                                allFilters: $allFilters,
                                messagesInScope: messagesInScope,
                                messageSelections: $messageSelections,
                                ascending: $ascending
                            )
                            .environmentObject(systemExtensionManager)
                            .environmentObject(userPrefs)
                        }
                    }
                }
                
                if viewExec && unifiedViewSelected {
                    Divider()
                }
                
                // MARK: Process Execute events will be displayed here (if enabled)
                if viewExec {
                    if #available(macOS 14, *) {
                        CustomizableSystemProcessExecTableView(
                            messages: execMessagesInScope,
                            messageSelections: $messageSelections,
                            allFilters: $allFilters,
                            ascending: $ascending
                        )
                        .environmentObject(systemExtensionManager)
                        .environmentObject(userPrefs)
                    } else {
                        SystemProcessExecTableView(
                            messages: execMessagesInScope,
                            messageSelections: $messageSelections,
                            allFilters: $allFilters,
                            ascending: $ascending
                        )
                        .environmentObject(systemExtensionManager)
                        .environmentObject(userPrefs)
                    }
                }
            }
        }
    }
}
