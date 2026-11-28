//
//  ActionMenuItem.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/25/26.
//

import AppKit


// MARK: - Action menu item
/// A menu item that runs a closure: the event tables' row menus, and the read-only text views' menus.
final class ActionMenuItem: NSMenuItem {
    private let handler: () -> Void

    /// - Parameters:
    ///   - title: The item's title.
    ///   - keyEquivalent: The shortcut it shows, with ⌘, or none.
    ///   - action: Runs when the item is chosen.
    init(title: String, keyEquivalent: String = "", action: @escaping () -> Void) {
        handler = action
        super.init(title: title, action: #selector(run), keyEquivalent: keyEquivalent)
        target = self
    }

    /// Not used: the item is made in code.
    ///
    /// - Parameter coder: Unused.
    required init(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    /// Run the closure, as choosing the item does.
    @objc private func run() { handler() }
}
