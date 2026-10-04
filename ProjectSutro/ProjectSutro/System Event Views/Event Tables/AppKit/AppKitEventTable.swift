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
/// A file dropped on the table is opened as a trace (`openFile`). The table takes the drop itself rather than leave it
/// to the window's SwiftUI `onDrop`, which a drop on an AppKit view inside it may never reach.
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
    /// Opens a file dropped on the table as a trace.
    let openFile: (URL) -> Void
    
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
        tableView.registerForDraggedTypes([.fileURL])
        
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
        
        // MARK: Dropping a trace
        /// Take a dropped file, highlighting the whole table rather than a row.
        ///
        /// - Parameters:
        ///   - tableView: The table.
        ///   - info: The drag.
        ///   - row: The row the drop would go before or on, which doesn't matter here.
        ///   - dropOperation: Before or on the row.
        /// - Returns: `.copy` for a file, nothing for anything else.
        func tableView(_ tableView: NSTableView, validateDrop info: NSDraggingInfo, proposedRow row: Int,
                       proposedDropOperation dropOperation: NSTableView.DropOperation) -> NSDragOperation {
            guard Self.droppedFile(info) != nil else { return [] }
            tableView.setDropRow(-1, dropOperation: .on)
            return .copy
        }
        
        /// Open a dropped file as a trace, once the drag has ended (opening may ask first).
        ///
        /// - Parameters:
        ///   - tableView: The table.
        ///   - info: The drag.
        ///   - row: Where the drop landed, which doesn't matter here.
        ///   - dropOperation: Before or on the row.
        /// - Returns: Whether the drop held a file.
        func tableView(_ tableView: NSTableView, acceptDrop info: NSDraggingInfo, row: Int,
                       dropOperation: NSTableView.DropOperation) -> Bool {
            guard let url = Self.droppedFile(info) else { return false }
            let openFile = parent.openFile
            DispatchQueue.main.async { openFile(url) }
            return true
        }
        
        /// - Parameter info: A drag.
        /// - Returns: The first file it carries, if any.
        private static func droppedFile(_ info: NSDraggingInfo) -> URL? {
            let urls = info.draggingPasteboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true])
            return (urls as? [URL])?.first
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
