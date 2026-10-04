//
//  AppKitEventTable.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/1/26.
//

import SwiftUI
import AppKit
import CoreData
import SutroESFramework


// MARK: - Columns
/// A column of an AppKit event table.
struct EventTableColumn {
    /// What a cell shows.
    enum Content {
        /// Monospaced text.
        case text((ESMessage) -> String, truncation: NSLineBreakMode = .byTruncatingTail, lines: Int = 1, selectable: Bool = false)
        /// One of the SwiftUI label views (event type, process name), hosted as is.
        case view((ESMessage) -> AnyView)
    }
    
    let title: String
    let width: (min: CGFloat, ideal: CGFloat, max: CGFloat)
    /// The `ESMessage` attribute the column sorts by.
    let sortKey: String
    /// Compare with `localizedStandardCompare:` (strings), like `TableColumn(_:value:)` does by default.
    var sortsAsText = true
    /// Can the column be hidden from the header's menu?
    var hideable = true
    var hiddenByDefault = false
    let content: Content
    
    /// - Parameter message: The event to show.
    /// - Returns: The text of a ``Content/text(_:truncation:lines:selectable:)`` cell.
    static func timestamp(_ message: ESMessage) -> String { eventTimeStamp(for: message) }
}

extension EventTableColumn {
    /// Offer the extra columns (hidden at first)? The SwiftUI tables of v2.1 and earlier only had them from macOS 14.
    private static var customizable: Bool {
        if #available(macOS 14, *) { return true } else { return false }
    }
    
    /// The "System Security Unified" table's columns: six on macOS 13 (where a missing user reads "Unknown"), nine from
    /// macOS 14.
    static var unified: [EventTableColumn] {
        var columns = [
            EventTableColumn(title: "Timestamp", width: (100, 100, 100), sortKey: "message_darwin_time", sortsAsText: false,
                             content: .text(timestamp)),
            EventTableColumn(title: "Event type", width: (150, 200, 400), sortKey: "es_event_type", hideable: false,
                             content: .view { AnyView(SystemEventTypeLabel(message: $0).truncationMode(.middle)) }),
            EventTableColumn(title: "Context", width: (100, 150, 2_000), sortKey: "context", hideable: false,
                             content: .text({ $0.context ?? "" }, truncation: .byTruncatingMiddle)),
            EventTableColumn(title: "Effective user", width: (80, 90, 120), sortKey: "initiating_euid_human",
                             content: .text({ $0.initiating_euid_human ?? (customizable ? "" : "Unknown") })),
            EventTableColumn(title: "Source process", width: (80, 100, 200), sortKey: "initiating_name",
                             content: .text({ $0.initiating_name ?? "" })),
        ]
        if customizable {
            columns += [
                EventTableColumn(title: "Initiating pid", width: (30, 50, 80), sortKey: "initiating_pid", sortsAsText: false,
                                 hiddenByDefault: true, content: .text({ String($0.initiating_pid) })),
                EventTableColumn(title: "ppid", width: (20, 30, 50), sortKey: "initiating_ppid", sortsAsText: false,
                                 hiddenByDefault: true, content: .text({ String($0.initiating_ppid) })),
                EventTableColumn(title: "Source process path", width: (50, 200, 500), sortKey: "initiating_path",
                                 hiddenByDefault: true, content: .text({ $0.initiating_path ?? "" }, truncation: .byTruncatingMiddle)),
            ]
        }
        columns.append(EventTableColumn(title: "Source Signing ID", width: (80, 100, 200), sortKey: "initiating_signing_id",
                                        content: .text({ $0.initiating_signing_id ?? "" })))
        return columns
    }
    
    /// The "Process Execution" table's columns. The timestamp starts hidden on macOS 14, like
    /// `CustomizableSystemProcessExecTableView`.
    static var exec: [EventTableColumn] {
        [
            EventTableColumn(title: "Timestamp", width: (100, 100, 100), sortKey: "message_darwin_time", sortsAsText: false,
                             hiddenByDefault: customizable, content: .text(timestamp)),
            EventTableColumn(title: "Process name", width: (80, 100, 400), sortKey: "created_name", hideable: false,
                             content: .view { AnyView(ProcessExecEventNameView(message: $0)) }),
            EventTableColumn(title: "Signing ID", width: (80, 100, 200), sortKey: "created_signing_id",
                             content: .text({ $0.created_signing_id ?? "" })),
            EventTableColumn(title: "Process path", width: (50, 60, 300), sortKey: "created_path",
                             content: .text({ $0.created_path ?? "" }, truncation: .byTruncatingMiddle, selectable: true)),
            EventTableColumn(title: "Command line", width: (200, 600, .infinity), sortKey: "exec_command_line", hideable: false,
                             content: .text({ $0.exec_command_line ?? "" }, lines: 8, selectable: true)),
        ]
    }
}


// MARK: - Table
/// An `NSTableView` of events. SwiftUI's `Table` can't keep up with millions of rows (#84).
///
/// It shows an ``EventTableQuery``'s rows (object IDs) and loads each event from the view context only while its row is
/// on screen. Its look (style, spacing, fonts, row heights, header) copies what SwiftUI's `Table` sets on the
/// `NSTableView` it uses underneath, so it matches the tables in the Event Facts windows.
///
/// Clicking a column header sorts by it (the model refetches). Right-clicking the header shows or hides columns, and
/// right-clicking (or Control-clicking) a row shows the event's menu (``EventRowMenu``). The
/// columns' layout survives SwiftUI rebuilding the table (e.g. the mini-chart toggle).
///
/// **Selection:** `selection` (event IDs) is shared with the other table and the "Export" menu. A
/// change made in this table is written to it, and a change made elsewhere is mapped back onto this table's rows (off
/// the main thread, since that means looking through every row).
struct AppKitEventTable: NSViewRepresentable {
    let model: EventQueryModel
    let query: EventTableQuery
    let columns: [EventTableColumn]
    /// The selected events, shared by every table.
    let selection: Binding<Set<UUID>>
    /// The row menus' filter items edit these.
    let filters: Binding<Filters>
    let manager: EndpointSecurityManager
    let prefs: UserPrefs
    /// Opens the "Event Facts" window.
    let openWindow: OpenWindowAction
    /// The columns' layout as saved in the scene (see ``ColumnLayout``), restored when the window is.
    let savedLayout: Binding<String>
    
    func makeCoordinator() -> Coordinator { Coordinator(self) }
    
    func makeNSView(context: Context) -> NSScrollView {
        let tableView = EventTableView()
        tableView.style = .inset
        tableView.rowSizeStyle = .custom
        tableView.rowHeight = 24
        tableView.usesAutomaticRowHeights = true
        tableView.intercellSpacing = NSSize(width: 17, height: 0)
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.backgroundColor = .controlBackgroundColor
        tableView.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        tableView.allowsMultipleSelection = true
        tableView.allowsEmptySelection = true
        tableView.allowsColumnReordering = true
        tableView.allowsColumnResizing = true
        tableView.floatsGroupRows = false
        /// Type select would need every row's text, which would load every event.
        tableView.allowsTypeSelect = false
        
        for column in columns {
            let tableColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(column.title))
            tableColumn.title = column.title
            tableColumn.headerCell.alignment = .left
            tableColumn.minWidth = column.width.min
            tableColumn.maxWidth = column.width.max
            tableColumn.width = column.width.ideal
            tableColumn.resizingMask = column.width.min == column.width.max ? [] : [.autoresizingMask, .userResizingMask]
            tableColumn.sortDescriptorPrototype = column.sortsAsText
                ? NSSortDescriptor(key: column.sortKey, ascending: true, selector: #selector(NSString.localizedStandardCompare(_:)))
                : NSSortDescriptor(key: column.sortKey, ascending: true)
            tableColumn.isHidden = column.hiddenByDefault
            tableView.addTableColumn(tableColumn)
        }
        /// Restore the layout of the table this one replaces, or else the one saved with the window.
        let layout = query.columnLayout.isEmpty ? ColumnLayout.decode(savedLayout.wrappedValue) : query.columnLayout
        for (position, saved) in layout.enumerated() {
            let index = tableView.column(withIdentifier: NSUserInterfaceItemIdentifier(saved.id))
            guard index >= 0, position < tableView.numberOfColumns else { continue }
            tableView.tableColumns[index].width = saved.width
            tableView.tableColumns[index].isHidden = saved.isHidden
            tableView.moveColumn(index, toColumn: position)
        }
        
        let headerMenu = NSMenu()
        headerMenu.delegate = context.coordinator
        tableView.headerView?.menu = headerMenu
        let rowMenu = NSMenu()
        rowMenu.autoenablesItems = false
        rowMenu.delegate = context.coordinator
        tableView.menu = rowMenu
        tableView.target = context.coordinator
        tableView.doubleAction = #selector(Coordinator.openEventFacts(_:))
        
        /// Before the data source is set, so restoring the sort doesn't trigger a refetch.
        tableView.sortDescriptors = query.sortDescriptors
        tableView.dataSource = context.coordinator
        tableView.delegate = context.coordinator
        query.tableView = tableView
        query.onReplace = { [weak coordinator = context.coordinator] in coordinator?.syncSelection() }
        context.coordinator.syncSelection(force: true)
        
        let scrollView = NSScrollView()
        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.borderType = .noBorder
        scrollView.drawsBackground = false
        return scrollView
    }
    
    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        context.coordinator.parent = self
        context.coordinator.syncSelection()
    }
    
    static func dismantleNSView(_ scrollView: NSScrollView, coordinator: Coordinator) {
        let query = coordinator.parent.query
        guard let tableView = scrollView.documentView as? NSTableView, query.tableView === tableView else { return }
        query.tableView = nil
        query.onReplace = nil
    }
    
    /// Fill whatever space SwiftUI offers, like `Table`.
    func sizeThatFits(_ proposal: ProposedViewSize, nsView: NSScrollView, context: Context) -> CGSize? {
        proposal.replacingUnspecifiedDimensions()
    }
    
    // MARK: Coordinator
    /// The table's data source and delegate.
    final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSMenuDelegate {
        var parent: AppKitEventTable
        /// The event last shown. AppKit asks for a row's cells one after another, and the view context doesn't keep
        /// events alive, so this saves loading the same event once per column.
        private var lastEvent: ESMessage?
        
        /// Bumped to cancel selection work still running.
        private var selectionRequest = 0
        /// The columns by identifier (their titles).
        private let columns: [String: EventTableColumn]
        
        init(_ parent: AppKitEventTable) {
            self.parent = parent
            columns = Dictionary(uniqueKeysWithValues: parent.columns.map { ($0.title, $0) })
        }
        
        /// The event in `row`, unless it's been deleted (e.g. by Clear).
        ///
        /// - Parameter row: A row of the table.
        /// - Returns: The event, fully loaded.
        private func event(at row: Int) -> ESMessage? {
            guard parent.query.rows.indices.contains(row) else { return nil }
            let id = parent.query.rows[row]
            if let lastEvent, lastEvent.objectID == id, !lastEvent.isDeleted { return lastEvent }
            lastEvent = try? parent.model.viewContext.existingObject(with: id) as? ESMessage
            return lastEvent?.isDeleted == false ? lastEvent : nil
        }
        
        func numberOfRows(in tableView: NSTableView) -> Int {
            parent.query.rows.count
        }
        
        func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
            guard let identifier = tableColumn?.identifier, let column = columns[identifier.rawValue], let message = event(at: row) else { return nil }
            
            switch column.content {
            case .text(let text, let truncation, let lines, let selectable):
                let cell = tableView.makeView(withIdentifier: identifier, owner: nil) as? EventTextCell
                    ?? EventTextCell(identifier: identifier, truncation: truncation, lines: lines, selectable: selectable)
                cell.textField?.stringValue = text(message)
                return cell
            case .view(let view):
                let cell = tableView.makeView(withIdentifier: identifier, owner: nil) as? EventHostingCell
                    ?? EventHostingCell(identifier: identifier)
                cell.show(view(message))
                return cell
            }
        }
        
        func tableView(_ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) {
            parent.query.sortDescriptors = tableView.sortDescriptors
            parent.model.reload()
        }
        
        // MARK: Selection
        /// The user changed the selection: share it.
        ///
        /// A few rows are looked up right away; a large selection (e.g. ⌘A) is looked up off the main thread and shared
        /// when that finishes.
        ///
        /// - Parameter notification: The table's selection change.
        func tableViewSelectionDidChange(_ notification: Notification) {
            let query = parent.query
            guard !query.isUpdating, let tableView = query.tableView, notification.object as? NSTableView === tableView else { return }
            let rows = query.rows
            let selected = tableView.selectedRowIndexes.compactMap { $0 < rows.count ? rows[$0] : nil }
            selectionRequest += 1
            let request = selectionRequest
            
            /// One small fetch is quick enough to do right away.
            guard selected.count > 500 else {
                return share((try? EventQueryModel.eventIDs(of: selected, context: parent.model.viewContext)) ?? [])
            }
            parent.model.eventIDs(of: selected) { [weak self] ids in
                guard let self, request == self.selectionRequest else { return }
                self.share(ids)
            }
        }
        
        /// - Parameter ids: The events the user selected in this table.
        private func share(_ ids: Set<UUID>) {
            parent.query.userSelected(ids)
            if parent.selection.wrappedValue != ids { parent.selection.wrappedValue = ids }
        }
        
        /// Select the rows holding the shared selection, if it changed elsewhere or the rows were replaced.
        ///
        /// - Parameter force: Look the selection up even if the table already shows it (e.g. a new table).
        func syncSelection(force: Bool = false) {
            let query = parent.query
            let wanted = parent.selection.wrappedValue
            query.selection = wanted
            guard force || wanted != query.shownSelection else { return }
            selectionRequest += 1
            let request = selectionRequest, version = query.version
            parent.model.indexes(of: wanted, in: query.rows) { [weak self] indexes in
                guard let self, request == self.selectionRequest else { return }
                /// Rows inserted meanwhile shift the indexes; rows replaced meanwhile mean looking again.
                guard let current = query.current(indexes, from: version) else { return self.syncSelection(force: true) }
                query.select(current, showing: wanted)
            }
        }
        
        // MARK: Menus
        /// Build the right-clicked row's menu, or the header's column menu.
        ///
        /// - Parameter menu: The table's row menu or its header's menu, about to open.
        func menuNeedsUpdate(_ menu: NSMenu) {
            menu.removeAllItems()
            guard let tableView = parent.query.tableView else { return }
            
            if menu === tableView.menu {
                /// Right-clicking below the last row shows no menu.
                guard tableView.clickedRow >= 0, let message = event(at: tableView.clickedRow) else { return }
                EventRowMenu(message: message, prefs: parent.prefs, filters: parent.filters, manager: parent.manager, openWindow: parent.openWindow)
                    .items().forEach(menu.addItem)
                return
            }
            
            /// List the columns that can be hidden, checked when shown.
            for tableColumn in tableView.tableColumns {
                guard columns[tableColumn.identifier.rawValue]?.hideable == true else { continue }
                let item = NSMenuItem(title: tableColumn.title, action: #selector(toggleColumn(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = tableColumn
                item.state = tableColumn.isHidden ? .off : .on
                menu.addItem(item)
            }
        }
        
        /// Open a double-clicked row's event in an "Event Facts" window, like the row menu's "Event metadata".
        ///
        /// - Parameter tableView: The double-clicked table. A double-click on the header or below the last row is ignored.
        @objc func openEventFacts(_ tableView: NSTableView) {
            guard tableView.clickedRow >= 0, let message = event(at: tableView.clickedRow) else { return }
            parent.openWindow(value: message.id)
        }
        
        /// Show or hide the column a header menu item stands for.
        ///
        /// - Parameter item: The chosen item; its `representedObject` is the column.
        @objc private func toggleColumn(_ item: NSMenuItem) {
            guard let tableColumn = item.representedObject as? NSTableColumn else { return }
            tableColumn.isHidden.toggle()
            saveLayout(of: tableColumn.tableView)
        }
        
        // MARK: Column layout
        /// Remember the columns' order, widths, and visibility on the query, so the table SwiftUI builds next (it builds
        /// the new one before taking this one down) looks the same.
        ///
        /// - Parameter tableView: The table whose columns changed.
        private func saveLayout(of tableView: NSTableView?) {
            guard let tableView, tableView === parent.query.tableView else { return }
            let layout = tableView.tableColumns.map { ColumnLayout(id: $0.identifier.rawValue, width: $0.width, isHidden: $0.isHidden) }
            parent.query.columnLayout = layout
            /// Columns also resize while SwiftUI lays out, when scene storage can't be written.
            let saved = parent.savedLayout, encoded = ColumnLayout.encode(layout)
            DispatchQueue.main.async { if saved.wrappedValue != encoded { saved.wrappedValue = encoded } }
        }
        
        func tableViewColumnDidMove(_ notification: Notification) {
            saveLayout(of: notification.object as? NSTableView)
        }
        
        func tableViewColumnDidResize(_ notification: Notification) {
            saveLayout(of: notification.object as? NSTableView)
        }
    }
}


// MARK: - Table view
/// The event tables' `NSTableView`, which takes right-clicks, Control-clicks, and double-clicks anywhere on a row itself.
///
/// Otherwise the cell under the pointer gets them first, and a text field there decides: a selectable one (Process path,
/// Command line) can show its own text menu, or no menu at all, and selects a word on a double-click. Sending them to the
/// table always opens the row's menu, or its Event Facts, with `clickedRow` set, wherever on the row the click lands.
final class EventTableView: NSTableView {
    /// - Parameter point: A point in the superview's coordinates.
    /// - Returns: The table itself for a click that opens a context menu or Event Facts, otherwise the usual hit view.
    override func hitTest(_ point: NSPoint) -> NSView? {
        let hit = super.hitTest(point)
        guard hit != nil, let event = NSApp.currentEvent else { return hit }
        switch event.type {
        case .rightMouseDown:
            return self
        case .leftMouseDown where event.modifierFlags.contains(.control) || event.clickCount == 2:
            return self
        default:
            return hit
        }
    }
}


// MARK: - Cells
/// A plain text cell, monospaced.
///
/// The label is the cell's `textField`, so AppKit turns it white on a selected row.
final class EventTextCell: NSTableCellView {
    /// - Parameters:
    ///   - identifier: The column's identifier, for reuse.
    ///   - truncation: How a single line truncates.
    ///   - lines: Wrap onto at most this many lines, truncating the last.
    ///   - selectable: Can the text be selected (and copied)?
    init(identifier: NSUserInterfaceItemIdentifier, truncation: NSLineBreakMode, lines: Int, selectable: Bool) {
        super.init(frame: .zero)
        self.identifier = identifier
        
        let label = lines > 1 ? NSTextField(wrappingLabelWithString: "") : NSTextField(labelWithString: "")
        label.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        label.textColor = .labelColor
        label.lineBreakMode = lines > 1 ? .byWordWrapping : truncation
        label.maximumNumberOfLines = lines
        label.cell?.truncatesLastVisibleLine = true
        label.isSelectable = selectable
        label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        addSubview(label)
        textField = label
        pin(label)
    }
    
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
}

/// A cell hosting one of the SwiftUI label views.
final class EventHostingCell: NSTableCellView {
    private let host = NSHostingView(rootView: AnyView(EmptyView()))
    private var content = AnyView(EmptyView())
    
    /// The row's selection look, which the hosted view needs to pick its text colors.
    override var backgroundStyle: NSView.BackgroundStyle {
        didSet { if backgroundStyle != oldValue { render() } }
    }
    
    /// - Parameter identifier: The column's identifier, for reuse.
    init(identifier: NSUserInterfaceItemIdentifier) {
        super.init(frame: .zero)
        self.identifier = identifier
        host.sizingOptions = [.intrinsicContentSize]
        host.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        addSubview(host)
        pin(host)
    }
    
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    
    /// - Parameter view: The label to show.
    func show(_ view: AnyView) {
        content = AnyView(view.lineLimit(1).frame(maxWidth: .infinity, alignment: .leading))
        render()
    }
    
    /// Show the label, telling it whether its row is selected (`backgroundProminence`) so its colors match the
    /// SwiftUI table's selected rows.
    private func render() {
        if #available(macOS 14, *) {
            host.rootView = AnyView(content.environment(\.backgroundProminence, backgroundStyle == .emphasized ? .increased : .standard))
        } else {
            host.rootView = content
        }
    }
}

private extension NSTableCellView {
    /// Fill the cell's width and center `view` vertically with 4 points above and below, the inset of SwiftUI's table
    /// cells. With automatic row heights this makes a single-line row 24 points tall.
    ///
    /// - Parameter view: The cell's content.
    func pin(_ view: NSView) {
        view.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            view.leadingAnchor.constraint(equalTo: leadingAnchor),
            view.trailingAnchor.constraint(equalTo: trailingAnchor),
            view.centerYAnchor.constraint(equalTo: centerYAnchor),
            view.topAnchor.constraint(greaterThanOrEqualTo: topAnchor, constant: 4),
        ])
    }
}


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
                         manager: systemExtensionManager, prefs: userPrefs, openWindow: openWindow, savedLayout: layout)
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
