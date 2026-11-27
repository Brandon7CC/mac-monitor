//
//  EnvironmentTable.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/25/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Environment table
/// An exec's environment variables in a Name and Value table, below a field that filters them by name or value.
/// A long environment shows its first rows and a link to show the rest. Right-clicking a row copies its variable,
/// name or value.
struct EnvironmentTable: View {
    /// The variables, in order.
    let variables: [EnvironmentVariable]
    /// The filter field's text.
    @Binding var filter: String
    /// Show every matching row, not only the first ones?
    @Binding var showsAll: Bool

    /// How many rows show before Show all.
    private static let collapsedCount = 8

    var body: some View {
        let matching = EnvironmentVariable.matching(filter, in: variables)
        let rows = showsAll ? matching : Array(matching.prefix(Self.collapsedCount))
        VStack(alignment: .leading) {
            SettingsSearchField(text: $filter, prompt: "Filter")
            table(rows)
            if matching.isEmpty {
                Text("No variables match.").foregroundStyle(.secondary)
            } else if rows.count < matching.count {
                Button("Show all \(matching.count)") { showsAll = true }
                    .buttonStyle(.link)
            }
        }
    }

    /// The rows under Name and Value headers, on alternating backgrounds.
    ///
    /// - Parameter rows: The rows to show.
    /// - Returns: The table.
    private func table(_ rows: [EnvironmentVariable]) -> some View {
        let nameWidth = Self.nameWidth(of: variables)
        let stripes = NSColor.alternatingContentBackgroundColors
        return VStack(alignment: .leading, spacing: 0) {
            line(Text("Name").bold(), Text("Value").bold(), nameWidth: nameWidth)
            ForEach(Array(rows.enumerated()), id: \.element.id) { index, variable in
                line(Text(variable.name).monospaced().foregroundStyle(Color(nsColor: PredicateSyntax.keyColor)),
                     Text(variable.value).monospaced(), nameWidth: nameWidth)
                    .background(Color(nsColor: stripes[index % stripes.count]))
                    .contentShape(Rectangle())
                    .contextMenu { copyMenu(variable) }
            }
        }
        /// No text selection, so a right-click opens the row's menu.
        .textSelection(.disabled)
    }

    /// A line of the table: a name beside its value, each wrapping.
    ///
    /// Every line's Name column has the same width, so the columns line up. It keeps that width as the filter
    /// changes.
    ///
    /// - Parameters:
    ///   - name: The name, or the Name header.
    ///   - value: The value, or the Value header.
    ///   - nameWidth: The Name column's width, from ``nameWidth(of:)``.
    /// - Returns: The line.
    private func line(_ name: some View, _ value: some View, nameWidth: CGFloat) -> some View {
        HStack(alignment: .top, spacing: 12) {
            name.fixedSize(horizontal: false, vertical: true)
                .frame(width: nameWidth, alignment: .topLeading)
            value.fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 3)
    }

    /// The widest the Name column gets, in points. A longer name wraps.
    private static let maxNameWidth: CGFloat = 280

    /// The Name column's width: the environment's longest name, or the header when it's wider, up to
    /// ``maxNameWidth``.
    ///
    /// - Parameter variables: The environment's variables, every one, so filtering doesn't change the width.
    /// - Returns: The width, in points.
    private static func nameWidth(of variables: [EnvironmentVariable]) -> CGFloat {
        let size = NSFont.systemFontSize
        let names = NSFont.monospacedSystemFont(ofSize: size, weight: .regular)
        let widest = variables.map { ($0.name as NSString).size(withAttributes: [.font: names]).width }.max() ?? 0
        let header = ("Name" as NSString).size(withAttributes: [.font: NSFont.boldSystemFont(ofSize: size)]).width
        return min(max(widest, header).rounded(.up) + 1, maxNameWidth)
    }

    /// A row's context menu.
    ///
    /// - Parameter variable: The row's variable.
    /// - Returns: Copy Variable, Copy Name and Copy Value.
    @ViewBuilder
    private func copyMenu(_ variable: EnvironmentVariable) -> some View {
        Button("Copy Variable") { Self.copy(variable.variable) }
        Button("Copy Name") { Self.copy(variable.name) }
        Button("Copy Value") { Self.copy(variable.value) }
    }

    /// Put text on the pasteboard.
    ///
    /// - Parameter text: The text.
    private static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
