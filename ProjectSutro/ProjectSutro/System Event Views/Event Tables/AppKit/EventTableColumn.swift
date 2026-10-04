//
//  EventTableColumn.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import SwiftUI
import AppKit
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
