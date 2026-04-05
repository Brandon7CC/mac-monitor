//
//  SystemEventsTableController.swift
//  ProjectSutro
//
//  Base NSViewController for NSTableView-based system event tables.
//

import AppKit
import SutroESFramework
import Combine

enum TableType {
    case unified(customizable: Bool)
    case processExec(customizable: Bool)
}

protocol MessageTableControllerDelegate: AnyObject {
    func selectionDidChange(_ selectedIDs: Set<ESMessage.ID>)
    func sortDidChange(sortColumn: MessageTableColumnID?, ascending: Bool)
}

class SystemEventsTableController: NSViewController {
    
    weak var delegate: MessageTableControllerDelegate?
    
    var scrollView: NSScrollView!
    var tableView: NSTableView!
    
    private var _messageIndices: [Int] = []
    private var displayedIndices: [Int] = []
    
    private var _selectedIDs: Set<ESMessage.ID> = []
    var selectedIDs: Set<ESMessage.ID> {
        get { _selectedIDs }
        set {
            if _selectedIDs == newValue { return }
            _selectedIDs = newValue
            applySelectionFromIDs()
        }
    }
    
    var needsExplicitSort: Bool = false
    var sortColumn: MessageTableColumnID = .timestamp
    var sortAscending: Bool = false
    
    private let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter
    }()
    
    var sortedIndices: [Int] {
        needsExplicitSort ? displayedIndices : _messageIndices
    }
    
    override func loadView() {
        scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.borderType = .noBorder
        
        tableView = NSTableView()
        tableView.allowsMultipleSelection = true
        tableView.allowsColumnSelection = false
        tableView.allowsColumnReordering = true
        tableView.allowsColumnResizing = true
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.style = .fullWidth
        tableView.rowHeight = 20
        tableView.usesAutomaticRowHeights = false
        tableView.intercellSpacing = NSSize(width: 2, height: 0)
        
        tableView.dataSource = self
        tableView.delegate = self
        tableView.target = self
        tableView.doubleAction = #selector(handleTableDoubleClick(_:))
        
        scrollView.documentView = tableView
        view = scrollView
    }

    @objc private func handleTableDoubleClick(_ sender: Any?) {
        let row = tableView.clickedRow
        guard row >= 0 else { return }
        openMetadataForRow(row)
    }

    func openMetadataForRow(_ row: Int) {
        // Subclasses can override to open event metadata.
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupSortDescriptors()
        refreshDisplayedIndices()
    }
    
    func setupColumns(for type: TableType) {
        tableView.tableColumns.forEach { tableView.removeTableColumn($0) }
        
        let columns: [NSTableColumn]
        switch type {
        case .unified(let customizable):
            columns = MessageTableColumnFactory.createUnifiedColumns(isCustomizable: customizable)
        case .processExec(let customizable):
            columns = MessageTableColumnFactory.createProcessExecColumns(isCustomizable: customizable)
        }
        
        columns.forEach { tableView.addTableColumn($0) }

        switch type {
        case .unified:
            tableView.columnAutoresizingStyle = .sequentialColumnAutoresizingStyle
        case .processExec:
            tableView.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        }
    }
    
    private func setupSortDescriptors() {
        tableView.sortDescriptors = [
            NSSortDescriptor(key: MessageTableColumnID.timestamp.rawValue, ascending: false)
        ]
    }
    
    func setMessageIndices(_ messageIndices: [Int]) {
        let oldCount = _messageIndices.count
        let newCount = messageIndices.count
        let appendOnly = isAppendOnlyTransition(from: _messageIndices, to: messageIndices)

        _messageIndices = messageIndices

        if !needsExplicitSort && appendOnly && newCount >= oldCount {
            if newCount > oldCount {
                let insertedAtTopCount = newCount - oldCount
                let inserted = IndexSet(integersIn: 0..<insertedAtTopCount)
                tableView.beginUpdates()
                tableView.insertRows(at: inserted, withAnimation: [])
                tableView.endUpdates()
            }
            return
        }

        refreshDisplayedIndices()
        tableView.reloadData()
    }

    private func messageIndexForRow(_ row: Int) -> Int? {
        guard row >= 0 else { return nil }

        if needsExplicitSort {
            guard row < displayedIndices.count else { return nil }
            return displayedIndices[row]
        }

        let index = _messageIndices.count - 1 - row
        guard index >= 0, index < _messageIndices.count else { return nil }
        return _messageIndices[index]
    }
    
    func messageForRow(_ row: Int) -> ESMessage? {
        guard row >= 0 else { return nil }

        guard let messageIndex = messageIndexForRow(row) else { return nil }
        return EventStore.shared.getEvent(at: messageIndex)
    }
    
    private func applySelectionFromIDs() {
        if _selectedIDs.isEmpty {
            if !tableView.selectedRowIndexes.isEmpty {
                tableView.deselectAll(nil)
            }
            return
        }

        let indices: [Int]
        if needsExplicitSort {
            indices = displayedIndices.enumerated().compactMap { row, messageIndex in
                guard let msg = EventStore.shared.getEvent(at: messageIndex) else { return nil }
                return _selectedIDs.contains(msg.id) ? row : nil
            }
        } else {
            let total = _messageIndices.count
            indices = _messageIndices.enumerated().compactMap { index, messageIndex in
                guard let msg = EventStore.shared.getEvent(at: messageIndex) else { return nil }
                guard _selectedIDs.contains(msg.id) else { return nil }
                return total - 1 - index
            }
        }

        tableView.selectRowIndexes(IndexSet(indices), byExtendingSelection: false)
    }

    private func refreshDisplayedIndices() {
        if !needsExplicitSort {
            displayedIndices = []
            return
        }

        displayedIndices = _messageIndices.sorted { idx1, idx2 in
            guard let msg1 = EventStore.shared.getEvent(at: idx1),
                  let msg2 = EventStore.shared.getEvent(at: idx2) else {
                return idx1 < idx2
            }

            let lhsLess = compareMessages(msg1, msg2, by: sortColumn)
            let rhsLess = compareMessages(msg2, msg1, by: sortColumn)

            if lhsLess == rhsLess {
                return msg1.mach_time < msg2.mach_time
            }

            return sortAscending ? lhsLess : rhsLess
        }
    }

    private func isAppendOnlyTransition(from old: [Int], to new: [Int]) -> Bool {
        guard new.count >= old.count else { return false }
        guard !old.isEmpty else { return true }

        let oldCount = old.count
        let mid = oldCount / 2

        return new[0] == old[0]
            && new[mid] == old[mid]
            && new[oldCount - 1] == old[oldCount - 1]
    }
    
    func compareMessages(_ msg1: ESMessage, _ msg2: ESMessage, by column: MessageTableColumnID) -> Bool {
        switch column {
        case .timestamp:
            return msg1.message_darwin_time < msg2.message_darwin_time
        case .eventType:
            return msg1.es_event_type < msg2.es_event_type
        case .context:
            return (msg1.context ?? "") < (msg2.context ?? "")
        case .effectiveUser:
            return (msg1.process.euid_human ?? "") < (msg2.process.euid_human ?? "")
        case .sourceProcess:
            return (msg1.process.executable?.name ?? "") < (msg2.process.executable?.name ?? "")
        case .initiatingPID:
            return msg1.process.pid < msg2.process.pid
        case .ppid:
            return msg1.process.ppid < msg2.process.ppid
        case .sourceProcessPath:
            return (msg1.process.executable?.path ?? "") < (msg2.process.executable?.path ?? "")
        case .sourceSigningID:
            return (msg1.process.signing_id ?? "") < (msg2.process.signing_id ?? "")
        case .processName:
            return (msg1.event.exec?.target.executable?.name ?? "") < (msg2.event.exec?.target.executable?.name ?? "")
        case .signingID:
            return (msg1.event.exec?.target.signing_id ?? "") < (msg2.event.exec?.target.signing_id ?? "")
        case .processPath:
            return (msg1.event.exec?.target.executable?.path ?? "") < (msg2.event.exec?.target.executable?.path ?? "")
        case .commandLine:
            return (msg1.event.exec?.command_line ?? "") < (msg2.event.exec?.command_line ?? "")
        }
    }
    
    func formatTimestamp(_ message: ESMessage) -> String {
        return dateFormatter.string(from: message.message_darwin_time)
    }
}

extension SystemEventsTableController: NSTableViewDataSource {
    func numberOfRows(in tableView: NSTableView) -> Int {
        return needsExplicitSort ? displayedIndices.count : _messageIndices.count
    }
}

extension SystemEventsTableController: NSTableViewDelegate {
    func tableViewSelectionDidChange(_ notification: Notification) {
        let selectedRowIndexes = tableView.selectedRowIndexes
        let newSelection: Set<ESMessage.ID> = Set(selectedRowIndexes.compactMap { index -> ESMessage.ID? in
            messageForRow(index)?.id
        })
        
        _selectedIDs = newSelection
        delegate?.selectionDidChange(newSelection)
    }
    
    func tableView(_ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) {
        guard let sortDescriptor = tableView.sortDescriptors.first else { return }
        
        if let columnID = MessageTableColumnID(rawValue: sortDescriptor.key ?? "") {
            sortColumn = columnID
            sortAscending = sortDescriptor.ascending
            // Default live-monitoring mode: newest events at the top.
            // Keep this path append-optimized (no explicit sort array) when
            // sorting by timestamp descending.
            if sortColumn == .timestamp && !sortAscending {
                needsExplicitSort = false
                displayedIndices = []
            } else {
                needsExplicitSort = true
                refreshDisplayedIndices()
            }
            tableView.reloadData()
            delegate?.sortDidChange(sortColumn: sortColumn, ascending: sortAscending)
        }
    }
}
