//
//  EditorStatusBar.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/25/26.
//

import SwiftUI


// MARK: - Status bar
/// The bar under a read-only text: the cursor's line and column, and how much is selected, which opens Go to Line
/// (⌘L), then the language, the options menu (wrapping and text size), and the text's lines and size.
struct EditorStatusBar: View {
    @ObservedObject var status: EditorStatus
    let controller: ReadOnlyTextController

    var body: some View {
        HStack(spacing: 12) {
            Button { status.isGoingToLine = true } label: { Text(position) }
                .buttonStyle(.plain)
                .help("Go to Line (⌘L)")
                .popover(isPresented: $status.isGoingToLine, arrowEdge: .top) {
                    GoToLineField(lineCount: status.lineCount) { line in
                        status.isGoingToLine = false
                        controller.goTo(line: line)
                    }
                }
            Text(status.language)
            Spacer(minLength: 8)
            Button { controller.showOptions() } label: { Image(systemName: "textformat.size") }
                .buttonStyle(.plain)
                .help("Wrap lines and change the text's size")
                .accessibilityLabel("Text options")
            Text("\(status.lineCount.formatted()) \(status.lineCount == 1 ? "line" : "lines") · "
                 + ByteCountFormatter.string(fromByteCount: Int64(status.byteCount), countStyle: .file))
        }
        .font(.system(size: 11))
        .monospacedDigit()
        .foregroundStyle(.secondary)
        .lineLimit(1)
        .padding(.horizontal, 8)
        .frame(height: 22)
    }

    /// "Line 12, Column 5", and "(30 selected)" while text is.
    private var position: String {
        let place = "Line \(status.line), Column \(status.column)"
        return status.selected > 0 ? "\(place) (\(status.selected.formatted()) selected)" : place
    }
}


// MARK: - Go to Line
/// A field for a line's number: Return goes to it, and Escape closes the popover.
struct GoToLineField: View {
    let lineCount: Int
    let go: (Int) -> Void
    @State private var entry = ""
    @FocusState private var isFocused: Bool

    var body: some View {
        TextField("Line", text: $entry, prompt: Text("Line, 1 to \(String(lineCount))"))
            .textFieldStyle(.roundedBorder)
            .monospacedDigit()
            .frame(width: 170)
            .focused($isFocused)
            .onSubmit {
                if let line = Int(entry.trimmingCharacters(in: .whitespaces)) { go(line) }
            }
            .padding(10)
            .onAppear { isFocused = true }
    }
}
