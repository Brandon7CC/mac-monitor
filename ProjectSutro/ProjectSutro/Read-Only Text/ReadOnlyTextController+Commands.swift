//
//  ReadOnlyTextController+Commands.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/25/26.
//

import AppKit
import SutroESFramework


// MARK: - Commands
/// What a read-only text view does besides showing text: its options menu and shortcuts, Go to Line, and copying.
enum EditorCommand: CaseIterable {
    case goToLine, wrapLines, bigger, smaller, actualSize

    /// Its menu item's title.
    var title: String {
        switch self {
        case .goToLine: "Go to Line…"
        case .wrapLines: "Wrap Lines"
        case .bigger: "Bigger"
        case .smaller: "Smaller"
        case .actualSize: "Actual Size"
        }
    }

    /// The key that runs it with ⌘ while the text is focused, as its menu item shows it.
    var key: String {
        switch self {
        case .goToLine: "l"
        case .wrapLines: ""
        case .bigger: "+"
        case .smaller: "-"
        case .actualSize: "0"
        }
    }

    /// The command a key press runs while the text is focused: ⌘L, ⌘+ (or ⌘=), ⌘- and ⌘0.
    ///
    /// - Parameter event: A key press.
    init?(_ event: NSEvent) {
        let modifiers = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
            .subtracting([.shift, .numericPad, .function, .capsLock])
        guard modifiers == .command, let key = event.charactersIgnoringModifiers?.lowercased(), !key.isEmpty,
              let command = key == "=" ? Self.bigger : Self.allCases.first(where: { $0.key == key }) else { return nil }
        self = command
    }
}


extension ReadOnlyTextController {
    /// Run a command.
    ///
    /// - Parameter command: The command.
    func perform(_ command: EditorCommand) {
        let defaults = UserDefaults.standard
        let size = defaults.object(forKey: EditorPreferences.textSizeKey) as? Double ?? EditorPreferences.defaultSize
        switch command {
        case .goToLine:
            status.isGoingToLine = true
        case .wrapLines:
            defaults.set(!wrapsLines, forKey: EditorPreferences.wrapsLinesKey)
        case .bigger, .smaller, .actualSize:
            let step = command == .bigger ? 1.0 : command == .smaller ? -1.0 : 0
            let next = step == 0 ? EditorPreferences.defaultSize : size + step
            defaults.set(min(max(next, EditorPreferences.sizes.lowerBound), EditorPreferences.sizes.upperBound),
                         forKey: EditorPreferences.textSizeKey)
        }
    }

    /// Show the options menu where the pointer is: Go to Line, Wrap Lines and the text size, with their shortcuts.
    func showOptions() {
        let menu = NSMenu()
        for command in EditorCommand.allCases {
            if command == .wrapLines || command == .bigger { menu.addItem(.separator()) }
            let item = ActionMenuItem(title: command.title, keyEquivalent: command.key) { [weak self] in
                self?.perform(command)
            }
            item.state = command == .wrapLines && wrapsLines ? .on : .off
            item.isEnabled = switch command {
            case .bigger: textSize < CGFloat(EditorPreferences.sizes.upperBound)
            case .smaller: textSize > CGFloat(EditorPreferences.sizes.lowerBound)
            case .actualSize: textSize != CGFloat(EditorPreferences.defaultSize)
            case .goToLine, .wrapLines: true
            }
            menu.addItem(item)
        }
        menu.autoenablesItems = false
        menu.popUp(positioning: nil, at: NSEvent.mouseLocation, in: nil)
    }

    /// Select a line and scroll to it, unfolding what hides it, then focus the text.
    ///
    /// - Parameter number: The line, from 1. One out of range is the first or last.
    func goTo(line number: Int) {
        guard let textView else { return }
        let range = lines.range(of: number - 1)
        reveal(range.location)
        let shown = folds.shown(range)
        textView.window?.makeFirstResponder(textView)
        textView.setSelectedRange(shown)
        textView.scrollRangeToVisible(shown)
        textView.showFindIndicator(for: shown.length > 0 ? shown : NSRange(location: shown.location, length: 0))
    }

    // MARK: Copying
    /// The selection's text, with what any fold in it hides, for Copy.
    ///
    /// - Returns: The text, or `nil` when nothing is folded and the view's own copy serves.
    func selectedText() -> String? {
        guard let textView, !folds.shown.isEmpty else { return nil }
        return original.substring(with: folds.original(textView.selectedRange()))
    }

    /// The items a right-click on an event's record offers for the value there: Copy Value, Copy Key Path and Copy as
    /// Predicate (``ValuePredicate``).
    ///
    /// - Parameter offset: Where the click is, in the text shown.
    /// - Returns: The items for a click on a key, a string's or a scalar's text, or an object's or array's brackets or
    ///   placeholder. None elsewhere, or for text that isn't a record.
    func valueItems(atShown offset: Int) -> [NSMenuItem] {
        let clicked = folds.original(offset)
        guard readsKeyPaths, let outline, let index = outline.value(at: clicked) else { return [] }
        let value = outline.values[index], text = original
        /// A placeholder's offsets map to its container's open bracket.
        let isOnValue = value.key.map { NSLocationInRange(clicked, $0) } == true || value.container.map {
            clicked == outline.containers[$0].open || clicked == outline.containers[$0].close
        } ?? NSLocationInRange(clicked, value.range)
        guard isOnValue else { return [] }
        var items = [ActionMenuItem(title: "Copy Value") { Self.copy(outline.copiedText(of: index, in: text)) }]
        if !value.keyPath.isEmpty {
            items.append(ActionMenuItem(title: "Copy Key Path") { Self.copy(value.keyPath) })
        }
        if let predicate = ValuePredicate.predicate(for: index, in: outline, text: text) {
            items.append(ActionMenuItem(title: "Copy as Predicate") { Self.copy(predicate) })
        }
        return items
    }

    /// Put text on the pasteboard.
    ///
    /// - Parameter text: The text.
    static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
