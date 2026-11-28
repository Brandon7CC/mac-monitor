//
//  CodeTextView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/25/26.
//

import AppKit


// MARK: - Code text view
/// The read-only text view: it highlights the cursor's line as Xcode does, takes the editor's shortcuts while it's
/// focused (``EditorCommand``), offers a record's value menu on a right-click, copies the text folds hide, and unfolds
/// a placeholder that's clicked. It wraps lines or scrolls sideways (``wrapsLines``).
final class CodeTextView: NSTextView {
    weak var controller: ReadOnlyTextController?

    /// The cursor's line, a tint under the text in light and dark.
    private static let currentLineColor = NSColor.appearance(light: .hex(0xE8F2FF), dark: .hex(0x2A2D33))

    /// Wrap long lines to the view's width, rather than scroll sideways?
    var wrapsLines = true {
        didSet { if wrapsLines != oldValue { layOutLines() } }
    }

    /// Lay the text out to the view's width, or as wide as its longest line.
    private func layOutLines() {
        guard let container = textContainer, let scrollView = enclosingScrollView else { return }
        let size = scrollView.contentSize
        scrollView.hasHorizontalScroller = !wrapsLines
        isHorizontallyResizable = !wrapsLines
        container.widthTracksTextView = wrapsLines
        container.containerSize = NSSize(width: wrapsLines ? size.width : CGFloat.greatestFiniteMagnitude,
                                         height: CGFloat.greatestFiniteMagnitude)
        /// Unwrapped, the view is never narrower than the scroll view, so the cursor's line spans it.
        minSize = wrapsLines ? .zero : size
        if wrapsLines {
            setFrameSize(NSSize(width: size.width, height: frame.height))
            scrollView.contentView.scroll(to: NSPoint(x: 0, y: scrollView.contentView.bounds.minY))
            scrollView.reflectScrolledClipView(scrollView.contentView)
        }
        sizeToFit()
        needsDisplay = true
    }

    /// Unwrapped, fit the view to its text again when the scroll view resizes.
    ///
    /// - Parameter oldSize: The scroll view's size before.
    override func resize(withOldSuperviewSize oldSize: NSSize) {
        super.resize(withOldSuperviewSize: oldSize)
        guard !wrapsLines, let scrollView = enclosingScrollView else { return }
        minSize = scrollView.contentSize
        sizeToFit()
    }

    // MARK: Drawing
    /// The background, then the cursor's line over it, when nothing is selected.
    ///
    /// - Parameter rect: The rectangle to draw.
    override func drawBackground(in rect: NSRect) {
        super.drawBackground(in: rect)
        guard let line = currentLineRect(), line.intersects(rect) else { return }
        Self.currentLineColor.setFill()
        line.intersection(rect).fill()
    }

    /// - Returns: Where the cursor's line is drawn, every line fragment it wraps to and the view's full width, or
    ///   `nil` while text is selected.
    private func currentLineRect() -> NSRect? {
        guard selectedRange().length == 0, let layoutManager, let storage = textStorage else { return nil }
        let caret = selectedRange().location
        let line = storage.mutableString.lineRange(for: NSRange(location: min(caret, storage.length), length: 0))
        var rect: NSRect
        if line.length == 0 {
            rect = layoutManager.extraLineFragmentRect
            guard rect.height > 0 else { return nil }
        } else {
            let glyphs = layoutManager.glyphRange(forCharacterRange: line, actualCharacterRange: nil)
            guard glyphs.length > 0 else { return nil }
            rect = layoutManager.lineFragmentRect(forGlyphAt: glyphs.location, effectiveRange: nil)
                .union(layoutManager.lineFragmentRect(forGlyphAt: NSMaxRange(glyphs) - 1, effectiveRange: nil))
        }
        return NSRect(x: bounds.minX, y: rect.minY + textContainerOrigin.y, width: bounds.width, height: rect.height)
    }

    // MARK: Keys, menus and clicks
    /// The editor's shortcuts, while the text is focused: before the main menu, so ⌘0 sets the text's size here
    /// rather than the window's tables.
    ///
    /// - Parameter event: A key press with a modifier.
    /// - Returns: Was it handled?
    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        if window?.firstResponder === self, let controller, let command = EditorCommand(event) {
            controller.perform(command)
            return true
        }
        return super.performKeyEquivalent(with: event)
    }

    /// The text view's own menu, without its editing items, after a record's value menu for the value clicked.
    ///
    /// - Parameter event: The right-click.
    /// - Returns: The menu.
    override func menu(for event: NSEvent) -> NSMenu? {
        let menu = super.menu(for: event) ?? NSMenu()
        Self.dropEditingItems(from: menu)
        guard let controller, let index = characterIndex(at: convert(event.locationInWindow, from: nil),
                                                         onGlyph: true) else { return menu }
        let items = controller.valueItems(atShown: index)
        guard !items.isEmpty else { return menu }
        if !menu.items.isEmpty { menu.insertItem(.separator(), at: 0) }
        for item in items.reversed() { menu.insertItem(item, at: 0) }
        return menu
    }

    /// The actions of NSTextView's menu items that change text or set up typing. The text can't be edited, so
    /// they're left out: Cut, Paste, Delete, and the Font, Spelling and Grammar, Substitutions, Transformations and
    /// Layout Orientation submenus.
    private static let editingActions: Set<Selector> = [
        #selector(cut(_:)), #selector(paste(_:)), #selector(pasteAsPlainText(_:)), #selector(pasteAsRichText(_:)),
        #selector(delete(_:)), #selector(NSFontManager.orderFrontFontPanel(_:)), #selector(showGuessPanel(_:)),
        #selector(checkSpelling(_:)), #selector(toggleContinuousSpellChecking(_:)),
        #selector(orderFrontSubstitutionsPanel(_:)), #selector(uppercaseWord(_:)),
        #selector(changeLayoutOrientation(_:)),
    ]

    /// Remove a menu's editing items, and each submenu that holds one, then the separators that leaves at an end
    /// or next to each other.
    ///
    /// - Parameter menu: NSTextView's menu.
    private static func dropEditingItems(from menu: NSMenu) {
        /// - Parameter item: A menu item.
        /// - Returns: Does it, or its submenu, edit text?
        func edits(_ item: NSMenuItem) -> Bool {
            item.action.map(editingActions.contains) == true || item.submenu?.items.contains(where: edits) == true
        }
        for item in menu.items.reversed() where edits(item) { menu.removeItem(item) }
        var afterSeparator = true
        for item in menu.items {
            if item.isSeparatorItem, afterSeparator { menu.removeItem(item) }
            afterSeparator = item.isSeparatorItem
        }
        if let last = menu.items.last, last.isSeparatorItem { menu.removeItem(last) }
    }

    /// Copy the selection with what any fold in it hides.
    ///
    /// - Parameter sender: The Copy command's sender.
    override func copy(_ sender: Any?) {
        guard let text = controller?.selectedText() else { return super.copy(sender) }
        ReadOnlyTextController.copy(text)
    }

    /// A plain click on a fold's placeholder focuses the text and unfolds it. A click with a modifier selects as usual.
    ///
    /// - Parameter event: The click.
    override func mouseDown(with event: NSEvent) {
        let isPlain = event.modifierFlags.intersection([.shift, .command, .option, .control]).isEmpty
        if event.clickCount == 1, isPlain, let controller,
           let index = characterIndex(at: convert(event.locationInWindow, from: nil), onGlyph: true) {
            window?.makeFirstResponder(self)
            if controller.unfoldPlaceholder(atShown: index) { return }
        }
        super.mouseDown(with: event)
    }

    /// The character at a point.
    ///
    /// - Parameters:
    ///   - point: A point in the view.
    ///   - onGlyph: Must the point be on the character's glyph, rather than nearest it?
    /// - Returns: The character's offset in the text shown, or `nil` for no text there.
    func characterIndex(at point: NSPoint, onGlyph: Bool) -> Int? {
        guard let layoutManager, let textContainer, let storage = textStorage, storage.length > 0 else { return nil }
        let inContainer = NSPoint(x: point.x - textContainerOrigin.x, y: point.y - textContainerOrigin.y)
        let index = layoutManager.characterIndex(for: inContainer, in: textContainer,
                                                 fractionOfDistanceBetweenInsertionPoints: nil)
        guard index < storage.length else { return nil }
        guard onGlyph else { return index }
        let glyphs = layoutManager.glyphRange(forCharacterRange: NSRange(location: index, length: 1),
                                              actualCharacterRange: nil)
        return layoutManager.boundingRect(forGlyphRange: glyphs, in: textContainer).contains(inContainer) ? index : nil
    }
}
