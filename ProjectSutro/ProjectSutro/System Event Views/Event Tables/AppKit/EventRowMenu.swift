//
//  EventRowMenu.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/2/26.
//

import SwiftUI
import AppKit
import SutroESFramework


// MARK: - Row menu
/// The right-click menu of a row in the AppKit event tables: ``EventMenuEntry/entries(_:isOn:)`` as menu items, the
/// same menu the SwiftUI tables (``EventMenuView``) and Settings > Context Menus draw.
///
/// Everything an item needs is read when the menu is built. An item never touches the event again, which may have been
/// cleared by the time the item is chosen.
@MainActor
struct EventRowMenu {
    /// The right-clicked event.
    let message: ESMessage
    let prefs: UserPrefs
    let filters: Binding<Filters>
    let manager: EndpointSecurityManager
    /// Opens the "Event Facts" window for an event.
    let openWindow: OpenWindowAction
    
    /// The event's menu as AppKit menu items, each item running its ``EventMenuAction``.
    ///
    /// - Returns: The menu's items: the process execution menu for `EXEC` events, the general one for everything else,
    ///   and none for an event without a type.
    func items() -> [NSMenuItem] {
        guard let facts = EventMenuFacts(message: message, isRecorded: !manager.coreDataContainer.isShowingTrace)
        else { return [] }
        let filters = filters, manager = manager, openWindow = openWindow
        return EventMenuEntry.entries(facts, prefs: prefs).map { entry -> NSMenuItem in
            switch entry {
            case .item(let title, let action):
                return ActionMenuItem(title: title) {
                    action.perform(filters: filters, manager: manager, openWindow: openWindow)
                }
            case .header(let title):
                let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
                item.isEnabled = false
                return item
            case .separator:
                return .separator()
            }
        }
    }
}


// MARK: - Action menu item
/// A menu item that runs a closure.
private final class ActionMenuItem: NSMenuItem {
    private let handler: () -> Void
    
    /// - Parameters:
    ///   - title: The item's title.
    ///   - action: Runs when the item is chosen.
    init(title: String, action: @escaping () -> Void) {
        handler = action
        super.init(title: title, action: #selector(run), keyEquivalent: "")
        target = self
    }
    
    required init(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    
    @objc private func run() { handler() }
}
