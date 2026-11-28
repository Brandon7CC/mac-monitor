//
//  ReadOnlyTextEditor.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/25/26.
//

import SwiftUI


// MARK: - Editor
/// A read-only text as a code editor shows it: for an event's record, the key path at the cursor above it
/// (``KeyPathBar``), then the text (``ReadOnlyTextView``), then the status bar (``EditorStatusBar``). The views that
/// show it keep its controller, for Fold All and Unfold All in their headers (``EditorFoldButtons``).
struct ReadOnlyTextEditor: View {
    let text: String
    var language: ReadOnlyTextView.Language = .plain
    /// Show the key path bar and the value menu, for an event's record?
    var readsKeyPaths = false
    /// The text's controller. Its changes redraw the bars, not this view.
    let controller: ReadOnlyTextController

    var body: some View {
        VStack(spacing: 0) {
            if readsKeyPaths {
                KeyPathBar(status: controller.status)
                Divider()
            }
            ReadOnlyTextView(text: text, language: language, readsKeyPaths: readsKeyPaths, controller: controller)
            Divider()
            EditorStatusBar(status: controller.status, controller: controller)
        }
    }
}


// MARK: - Fold All and Unfold All
/// Fold All and Unfold All, for a JSON text's header.
struct EditorFoldButtons: View {
    @ObservedObject var controller: ReadOnlyTextController

    var body: some View {
        Button { controller.foldAll() } label: { Label("Fold All", systemImage: "rectangle.compress.vertical") }
            .labelStyle(.iconOnly)
            .help("Fold every object and array")
            .disabled(!controller.canFold)
        Button { controller.unfoldAll() } label: { Label("Unfold All", systemImage: "rectangle.expand.vertical") }
            .labelStyle(.iconOnly)
            .help("Unfold everything")
            .disabled(!controller.isFolded)
    }
}


// MARK: - Preferences
/// What every read-only text view shares, kept in the user's defaults: wrapping and the text's size.
enum EditorPreferences {
    static let wrapsLinesKey = "readOnlyTextWrapsLines"
    static let textSizeKey = "readOnlyTextSize"
    /// The text's size, in points, as it was before it could change.
    static let defaultSize = 12.0
    /// The sizes Bigger and Smaller step through, a point at a time.
    static let sizes = 8.0...28.0
}
