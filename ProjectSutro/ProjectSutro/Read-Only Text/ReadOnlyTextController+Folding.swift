//
//  ReadOnlyTextController+Folding.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/25/26.
//

import AppKit
import SutroESFramework


// MARK: - Folding
/// A JSON text's objects and arrays fold to a placeholder such as `{ 7 keys }`. The text view shows the text with each
/// fold's range replaced by its placeholder (``TextFolds``), and the text itself never changes: Copy, the status bar
/// and key paths read it through the folds. A fold inside a folded one stays folded when the outer one opens.
extension ReadOnlyTextController {
    /// Is the object or array that opens a line folded?
    ///
    /// - Parameter line: A line of the text, from 0.
    /// - Returns: `nil` when nothing folds from the line, else whether it's folded.
    func foldState(onLine line: Int) -> Bool? {
        outline?.foldable(onLine: line).map(folded.contains)
    }

    /// Fold or unfold the object or array that opens a line.
    ///
    /// - Parameter line: A line of the text, from 0.
    func toggleFold(onLine line: Int) {
        guard let container = outline?.foldable(onLine: line) else { return }
        toggle(container)
    }

    /// Fold an object or array, or unfold it.
    ///
    /// - Parameter container: Its place in the outline's containers.
    func toggle(_ container: Int) {
        guard let outline, outline.containers[container].isFoldable else { return }
        var folded = self.folded
        if folded.remove(container) == nil { folded.insert(container) }
        refold(folded, span: outline.values[outline.containers[container].value].range)
    }

    /// Fold every object and array inside each value at the top, so the top one shows its keys.
    func foldAll() {
        guard let outline else { return }
        let inside = outline.containers.indices.filter {
            outline.containers[$0].isFoldable && outline.values[outline.containers[$0].value].parent != nil
        }
        refold(Set(inside), span: NSRange(location: 0, length: original.length))
    }

    /// Unfold everything.
    func unfoldAll() {
        refold([], span: NSRange(location: 0, length: original.length))
    }

    /// Unfold the fold whose placeholder is at an offset in the text shown, as clicking it does.
    ///
    /// - Parameter offset: An offset in the text shown.
    /// - Returns: Was a placeholder there?
    func unfoldPlaceholder(atShown offset: Int) -> Bool {
        guard let index = folds.fold(atShown: offset), let container = container(of: index) else { return false }
        let start = folds.shown[index].range.location
        toggle(container)
        textView?.setSelectedRange(NSRange(location: folds.shown(start), length: 0))
        return true
    }

    /// Unfold whatever hides an offset, outermost first.
    ///
    /// - Parameter offset: An offset in the text.
    func reveal(_ offset: Int) {
        while let index = folds.fold(hiding: offset), folds.shown[index].range.location < offset,
              let container = container(of: index) {
            toggle(container)
        }
    }

    /// - Parameter index: A shown fold, by its place in ``folds``.
    /// - Returns: The container it folds, by its place in the outline's containers.
    private func container(of index: Int) -> Int? {
        guard let outline, let value = outline.value(at: folds.shown[index].range.location) else { return nil }
        return outline.values[value].container
    }

    /// Fold a new set of objects and arrays, replacing what the view shows for the span that changes, and keep the
    /// selection on the same text and the top line where it was.
    ///
    /// - Parameters:
    ///   - folded: The containers to fold.
    ///   - span: The range of the text whose folds change: a container's, or the whole text.
    private func refold(_ folded: Set<Int>, span: NSRange) {
        guard let outline, let storage = textView?.textStorage else { return }
        keepingPlace {
            let replaced = folds.shown(span)
            self.folded = folded
            folds = TextFolds(folded.map { index in
                let container = outline.containers[index]
                return TextFolds.Fold(range: outline.values[container.value].range, placeholder: container.summary)
            })
            storage.beginEditing()
            storage.replaceCharacters(in: replaced, with: rendered(span))
            storage.endEditing()
        }
        noteFolded(!folds.shown.isEmpty)
        selectionChanged()
    }

    /// Change the text shown, keeping the selection on the same text, or where its fold is, and the line at the top
    /// of the view at the top.
    ///
    /// - Parameter change: Changes the text shown and the folds.
    func keepingPlace(_ change: () -> Void) {
        clearBrackets()
        guard let textView, let layoutManager = textView.layoutManager, let container = textView.textContainer,
              let storage = textView.textStorage else { return change() }
        let selection = folds.original(textView.selectedRange())
        defer { textView.setSelectedRange(folds.shown(selection)) }
        let visible = textView.visibleRect
        let origin = textView.textContainerOrigin
        /// - Parameter offset: An offset in the text shown.
        /// - Returns: How far down the view the top of its line fragment is.
        func top(of offset: Int) -> CGFloat {
            let glyph = layoutManager.glyphIndexForCharacter(at: min(offset, storage.length - 1))
            return layoutManager.lineFragmentRect(forGlyphAt: glyph, effectiveRange: nil).minY + origin.y
        }
        guard storage.length > 0 else { return change() }
        let shownTop = layoutManager.characterIndex(for: NSPoint(x: 0, y: visible.minY - origin.y), in: container,
                                                    fractionOfDistanceBetweenInsertionPoints: nil)
        let start = lines.starts[lines.line(at: folds.original(shownTop))]
        let past = visible.minY - top(of: folds.shown(start))
        change()
        guard storage.length > 0 else { return }
        textView.scroll(NSPoint(x: visible.minX, y: max(top(of: folds.shown(start)) + past, 0)))
        gutter?.needsDisplay = true
    }
}
