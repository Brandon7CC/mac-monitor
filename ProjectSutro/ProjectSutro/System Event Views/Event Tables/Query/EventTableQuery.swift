//
//  EventTableQuery.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import AppKit
import CoreData
import SutroESFramework


// MARK: - Table query
/// The rows of one AppKit event table: the object IDs of the events that pass the filters, in the table's sort order.
///
/// Only object IDs are kept. The table asks the view context for the few events on screen, so a table costs about the
/// same whether it holds a hundred events or millions. ``EventQueryModel`` fills it from a background context and pushes
/// each change straight to the table view, never through SwiftUI (which would diff every row on every change).
///
/// Main thread only.
final class EventTableQuery {
    /// Newest first.
    static let defaultSort = [NSSortDescriptor(key: "message_darwin_time", ascending: false)]
    
    /// Only `EXEC` events (the Process Execution table)?
    let execOnly: Bool
    /// The sort chosen in the table's header. Fetches add `mach_time` descending to break ties.
    var sortDescriptors: [NSSortDescriptor] = defaultSort
    /// The columns' order, widths, and visibility, kept so a table rebuilt by SwiftUI (e.g. the mini-chart toggle) looks
    /// the same. Empty until the table's columns first change.
    var columnLayout: [ColumnLayout] = []
    /// The rows, top to bottom.
    private(set) var rows: [NSManagedObjectID] = []
    /// Bumped whenever `rows` changes, so work done against older rows can be recognized.
    private(set) var version = 0
    /// The table showing these rows, if one is on screen.
    weak var tableView: NSTableView?
    
    /// The rows each insert added since the rows were last replaced, so row indexes found earlier can be brought up to
    /// date (see ``current(_:from:)``) instead of looked up again.
    private var insertions: [(version: Int, indexes: IndexSet)] = []
    /// The oldest version ``current(_:from:)`` can bring up to date.
    private var oldestCurrentable = 0
    
    /// The events the table should show selected: the shared selection, kept current by the table. Reloads select them
    /// again in the new rows.
    var selection: Set<UUID> = []
    /// The selection the table's selected rows reflect. Lags `selection` while a new one is being found in the rows.
    private(set) var shownSelection: Set<UUID> = []
    /// Set while the rows or their selection are being changed in code, so the table doesn't take the change for the
    /// user's.
    private(set) var isUpdating = false
    /// Called after the rows are replaced, so the table can check its selection is still current.
    var onReplace: (() -> Void)?
    
    /// - Parameter execOnly: Only show `EXEC` events.
    init(execOnly: Bool) {
        self.execOnly = execOnly
    }
    
    /// The full fetch sort: the header's sort, then `mach_time` descending.
    var fetchSort: [NSSortDescriptor] { sortDescriptors + [NSSortDescriptor(key: "mach_time", ascending: false)] }
    
    /// Replace every row.
    ///
    /// - Parameters:
    ///   - rows: The new rows.
    ///   - indexes: The rows to select.
    ///   - shown: The selection those rows reflect.
    func replace(with rows: [NSManagedObjectID], selecting indexes: IndexSet = [], showing shown: Set<UUID>) {
        self.rows = rows
        version += 1
        insertions = []
        oldestCurrentable = version
        updating { tableView?.reloadData() }
        select(indexes, showing: shown)
        onReplace?()
    }
    
    /// Select rows to reflect a selection.
    ///
    /// - Parameters:
    ///   - indexes: The rows holding the selected events.
    ///   - shown: The selection they reflect.
    func select(_ indexes: IndexSet, showing shown: Set<UUID>) {
        shownSelection = shown
        updating { tableView?.selectRowIndexes(indexes, byExtendingSelection: false) }
    }
    
    /// The user selected rows holding the events `ids`.
    ///
    /// - Parameter ids: The selected events.
    func userSelected(_ ids: Set<UUID>) {
        selection = ids
        shownSelection = ids
    }
    
    /// - Parameter change: Changes the table in code.
    private func updating(_ change: () -> Void) {
        isUpdating = true
        defer { isUpdating = false }
        change()
    }
    
    /// Insert rows. The table keeps its other rows' views and shifts the selection to match.
    ///
    /// - Parameters:
    ///   - rows: The rows after the insert.
    ///   - indexes: Where the new rows are in `rows`.
    func insert(_ rows: [NSManagedObjectID], at indexes: IndexSet) {
        guard !indexes.isEmpty else { return }
        version += 1
        insertions.append((version, indexes))
        /// Keep a bounded history: indexes older than it are looked up again.
        if insertions.count > 64 { oldestCurrentable = insertions.removeFirst().version }
        /// A table that hasn't counted the current rows yet (e.g. just created) can only be reloaded.
        guard let tableView, tableView.numberOfRows == self.rows.count else {
            self.rows = rows
            updating { tableView?.reloadData() }
            return
        }
        updating {
            tableView.beginUpdates()
            self.rows = rows
            tableView.insertRows(at: indexes, withAnimation: [])
            tableView.endUpdates()
        }
    }
    
    /// Bring row indexes found in an older version of the rows up to date, shifting them past every row inserted since,
    /// the same way `insertRows(at:withAnimation:)` shifts a table's selection.
    ///
    /// - Parameters:
    ///   - indexes: Indexes into the rows as they were at `version`.
    ///   - version: The ``version`` they were found in.
    /// - Returns: The same rows' indexes now, or `nil` if the rows were replaced since (look them up again).
    func current(_ indexes: IndexSet, from version: Int) -> IndexSet? {
        guard version >= oldestCurrentable else { return nil }
        var result = indexes
        for insertion in insertions where insertion.version > version {
            /// Insert positions are in final coordinates, so shifting at each in ascending order lands every row right.
            insertion.indexes.forEach { result.shift(startingAt: $0, by: 1) }
        }
        return result
    }
}


// MARK: - Column layout
/// One column's place in a table's layout, saved so the columns look the same when the table is rebuilt or its window
/// restored. The layout is kept in scene storage.
struct ColumnLayout: Codable, Equatable {
    /// The column's identifier (its title).
    let id: String
    let width: CGFloat
    let isHidden: Bool
    
    /// - Parameter string: A layout from ``encode(_:)``.
    /// - Returns: The layout, or none if `string` is empty or unreadable.
    static func decode(_ string: String) -> [ColumnLayout] {
        (try? JSONDecoder().decode([ColumnLayout].self, from: Data(string.utf8))) ?? []
    }
    
    /// - Parameter layout: Every column, in order.
    /// - Returns: The layout as a string for scene storage.
    static func encode(_ layout: [ColumnLayout]) -> String {
        (try? JSONEncoder().encode(layout)).flatMap { String(data: $0, encoding: .utf8) } ?? ""
    }
}
