//
//  FileContentView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import AppKit
import SutroESFramework


// MARK: - File content
/// Text Mac Monitor read, such as the script an interpreter ran, a property list, or an event's JSON: its title above
/// it, its line count, Copy, and for a file still on disk Show in Finder, then the text, filling the rest of the tab
/// (``ReadOnlyTextView``).
struct FileContentView: View {
    /// What the text is, such as "Event JSON", or the file it's from.
    let title: String
    /// Is the title a path, shown monospaced?
    var titleIsPath = false
    /// The text.
    let content: String
    /// What the text is, for its colors.
    var language: ReadOnlyTextView.Language = .plain
    /// Where the text came from, as the tooltip of an info icon after the title, such as who named a script. `nil`
    /// shows no icon.
    var source: String? = nil

    var body: some View {
        let lineCount = content.lineCount
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Text(title).font(titleIsPath ? .body.monospaced().weight(.semibold) : .headline)
                    .lineLimit(1).truncationMode(.middle)
                    .textSelection(.enabled)
                    .help(title)
                if let source {
                    InfoTip(text: source)
                }
                Spacer(minLength: 8)
                Text("\(lineCount.formatted()) \(lineCount == 1 ? "line" : "lines")")
                    .foregroundStyle(.secondary).monospacedDigit()
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(content, forType: .string)
                } label: { Label("Copy", systemImage: "doc.on.doc") }
                    .help("Copy the text")
                if titleIsPath { ShowInFinderButton(path: title) }
            }
            ReadOnlyTextView(text: content, language: language)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(.separator))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

extension FileContentView {
    /// Text read from a file, under the file's path.
    ///
    /// - Parameters:
    ///   - path: The file the text is from.
    ///   - content: The text.
    ///   - language: What the text is, for its colors.
    ///   - source: Where the text came from, as an info icon's tooltip after the path, or `nil` for no icon.
    init(path: String, content: String, language: ReadOnlyTextView.Language = .plain, source: String? = nil) {
        self.init(title: path, titleIsPath: true, content: content, language: language, source: source)
    }
}


// MARK: - Show in Finder
/// Show in Finder for a file an event is about, while it's still there: a script, or a file created or renamed.
struct ShowInFinderButton: View {
    let path: String

    var body: some View {
        if !path.isEmpty, FileManager.default.fileExists(atPath: path) {
            Button {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
            } label: { Label("Show in Finder", systemImage: "folder") }
                .help("Show \(path.lastPathComponent) in the Finder")
        }
    }
}
