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
    let title: String
    /// Is the title a path, shown monospaced?
    let titleIsPath: Bool
    let content: String
    var language: ReadOnlyTextView.Language = .plain

    /// - Parameters:
    ///   - path: The file the text is from.
    ///   - content: The text.
    ///   - language: What the text is, for its colors.
    init(path: String, content: String, language: ReadOnlyTextView.Language = .plain) {
        title = path
        titleIsPath = true
        self.content = content
        self.language = language
    }

    /// - Parameters:
    ///   - title: What the text is, such as "Event JSON".
    ///   - content: The text.
    ///   - language: What the text is, for its colors.
    init(title: String, content: String, language: ReadOnlyTextView.Language = .plain) {
        self.title = title
        titleIsPath = false
        self.content = content
        self.language = language
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Text(title).font(titleIsPath ? .body.monospaced().weight(.semibold) : .headline)
                    .lineLimit(1).truncationMode(.middle)
                    .textSelection(.enabled)
                    .help(title)
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

    /// How many lines the text has.
    private var lineCount: Int {
        content.reduce(into: 1) { if $1 == "\n" { $0 += 1 } } - (content.hasSuffix("\n") ? 1 : 0)
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
