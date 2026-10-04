//
//  EventTableCells.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import SwiftUI
import AppKit


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
