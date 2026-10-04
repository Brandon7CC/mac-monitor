//
//  AppKitEventTablesView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Tables view
/// The main window's event tables: "System Security Unified" (with the mini-chart beside it) above "Process Execution",
/// each an ``AppKitEventTable`` fed by an ``EventQueryModel``.
struct AppKitEventTablesView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    @Environment(\.openWindow) private var openWindow
    
    @ObservedObject var model: EventQueryModel
    /// Track all filters set by the user
    @Binding var allFilters: Filters
    /// The currently selected events (i.e. table rows)
    @Binding var messageSelections: Set<ESMessage.ID>
    
    /// Should we display the "System Security Unified" table?
    @Binding var unifiedViewSelected: Bool
    /// Should we display the "Process Execution" table view?
    @Binding var viewExec: Bool
    /// Should we display the mini-chart?
    @Binding var viewMiniChart: Bool
    /// Opens a file dropped on a table as a trace.
    let openFile: (URL) -> Void
    
    /// Each table's column layout (see ``ColumnLayout``), kept with the window.
    @SceneStorage("UnifiedSystemTableColumns.v2") private var unifiedColumns: String = ""
    @SceneStorage("ProcessExecTableColumns.v2") private var execColumns: String = ""
    
    private var unifiedTable: some View {
        table(model.unified, columns: EventTableColumn.unified, layout: $unifiedColumns)
    }
    
    /// - Parameters:
    ///   - query: The table's rows.
    ///   - columns: The table's columns.
    ///   - layout: Where the table's column layout is saved.
    /// - Returns: An AppKit event table sharing the selection and filters.
    private func table(_ query: EventTableQuery, columns: [EventTableColumn], layout: Binding<String>) -> AppKitEventTable {
        AppKitEventTable(model: model, query: query, columns: columns, selection: $messageSelections, filters: $allFilters,
                         manager: systemExtensionManager, prefs: userPrefs, openWindow: openWindow, savedLayout: layout,
                         openFile: openFile)
    }
    
    /// The shortest either table's pane can be dragged to.
    private static let minimumPaneHeight: CGFloat = 120
    
    /// The tables are stacked in a split view, so the divider between them can be dragged. Where it was dragged isn't
    /// saved: every launch starts from the default layout.
    var body: some View {
        let hasEvents = model.filteredCount > 0
        VSplitView {
            if unifiedViewSelected {
                Form {
                    Section(header: Label("System Security Unified", systemImage: "apple.logo").font(.title2)) {
                        if viewMiniChart {
                            GeometryReader { geo in
                                HStack {
                                    unifiedTable
                                        .frame(width: geo.size.width * (hasEvents ? 0.80 : 1.0), height: geo.size.height)
                                    SystemChartEventView(counts: model.chartCounts)
                                        .frame(width: geo.size.width * (hasEvents ? 0.20 : 0.0), height: geo.size.height)
                                }
                            }
                        } else {
                            unifiedTable
                        }
                    }
                }
                .frame(minHeight: Self.minimumPaneHeight, maxHeight: .infinity)
            }
            
            // MARK: Process Execute events will be displayed here (if enabled)
            if viewExec {
                Form {
                    Section(header: Label("Process", systemImage: "cpu").font(.title2)) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("**Execution**")
                            table(model.exec, columns: EventTableColumn.exec, layout: $execColumns)
                        }
                    }
                }
                .frame(minHeight: Self.minimumPaneHeight, maxHeight: .infinity)
            }
        }
    }
}
