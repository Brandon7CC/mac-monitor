//
//  SystemEventsNSTableContainerView.swift
//  ProjectSutro
//
//  Container view that dispatches between Ventura and Sonoma NSTableView implementations.
//  Replaces SystemEventsTableView for NSTableView-based tables.
//

import SwiftUI
import SutroESFramework

struct SystemEventsNSTableContainerView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    
    var messageIndicesInScope: [Int]
    var execMessageIndicesInScope: [Int]
    var chartEventTypeCounts: [String: Int]
    
    @Binding var unifiedViewSelected: Bool
    @Binding var viewExec: Bool
    @Binding var viewMiniChart: Bool
    @Binding var ascending: Bool
    @Binding var allFilters: Filters
    @Binding var messageSelections: Set<ESMessage.ID>
    
    var body: some View {
        VStack(spacing: 0) {
            if unifiedViewSelected {
                Label("System Security Unified", systemImage: "apple.logo")
                    .font(.title2)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal)
                    .padding(.vertical, 4)
                
                if viewMiniChart {
                    GeometryReader { geo in
                        HStack {
                            if #unavailable(macOS 14) {
                                UnifiedSystemEventsNSTableView(
                                    messageIndices: messageIndicesInScope,
                                    messageSelections: $messageSelections,
                                    allFilters: $allFilters,
                                    ascending: $ascending
                                )
                                .frame(
                                    width: geo.size.width * (!messageIndicesInScope.isEmpty ? 0.80 : 1.0),
                                    height: geo.size.height
                                )
                                .environmentObject(systemExtensionManager)
                                .environmentObject(userPrefs)
                            } else {
                                CustomizableUnifiedSystemEventsNSTableView(
                                    messageIndices: messageIndicesInScope,
                                    messageSelections: $messageSelections,
                                    allFilters: $allFilters,
                                    ascending: $ascending
                                )
                                .frame(
                                    width: geo.size.width * (!messageIndicesInScope.isEmpty ? 0.80 : 1.0),
                                    height: geo.size.height
                                )
                                .environmentObject(systemExtensionManager)
                                .environmentObject(userPrefs)
                            }
                            
                            SystemChartEventView(eventTypeCounts: chartEventTypeCounts)
                                .frame(
                                    width: geo.size.width * (!messageIndicesInScope.isEmpty ? 0.20 : 0.0),
                                    height: geo.size.height
                                )
                        }
                    }
                } else {
                    if #unavailable(macOS 14) {
                        UnifiedSystemEventsNSTableView(
                            messageIndices: messageIndicesInScope,
                            messageSelections: $messageSelections,
                            allFilters: $allFilters,
                            ascending: $ascending
                        )
                        .environmentObject(systemExtensionManager)
                        .environmentObject(userPrefs)
                    } else {
                        CustomizableUnifiedSystemEventsNSTableView(
                            messageIndices: messageIndicesInScope,
                            messageSelections: $messageSelections,
                            allFilters: $allFilters,
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
            
            if viewExec {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Process", systemImage: "cpu")
                        .font(.title2)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Text("**Execution**")

                if #available(macOS 14, *) {
                    CustomizableSystemProcessExecNSTableView(
                        messageIndices: execMessageIndicesInScope,
                        messageSelections: $messageSelections,
                        allFilters: $allFilters,
                        ascending: $ascending
                    )
                    .environmentObject(systemExtensionManager)
                    .environmentObject(userPrefs)
                } else {
                    SystemProcessExecNSTableView(
                        messageIndices: execMessageIndicesInScope,
                        messageSelections: $messageSelections,
                        allFilters: $allFilters,
                        ascending: $ascending
                    )
                    .environmentObject(systemExtensionManager)
                    .environmentObject(userPrefs)
                }
                }
                .padding(.top, 4)
            }
        }
    }
}
