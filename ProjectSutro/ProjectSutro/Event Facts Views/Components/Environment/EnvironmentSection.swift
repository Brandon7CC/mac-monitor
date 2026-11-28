//
//  EnvironmentSection.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/27/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Environment section
/// The end of an exec's Metadata: its environment as `NAME=value` lines in one selectable text, in the order the
/// process got them, exactly as stored. A control character or line break draws as an escape, such as `\n`, so each
/// variable keeps one line. Compared with its launcher's environment (``EnvironmentComparison``), it shows the lines
/// that differ first, and Show all lists every line with the same ones dimmed. A field filters the lines by name or
/// value.
///
/// Give it the event's identity (`.id(message.objectID)`), so each event starts unfiltered, showing what differs.
struct EnvironmentSection: View {
    /// The exec's variables and their comparison, read once for the event.
    @StateObject private var reading: EnvironmentReading
    /// The filter field's text.
    @State private var filter = ""
    /// Show every line, not only the ones that differ?
    @State private var showsAll = false

    /// The most lines drawn. A trace can hold an environment of tens of thousands.
    private static let maxLines = 1_000

    /// - Parameter message: The exec, in the view context.
    init(message: ESMessage) {
        _reading = StateObject(wrappedValue: EnvironmentReading(message: message))
    }

    /// Nothing for an exec without variables, or one that's gone.
    var body: some View {
        let variables = reading.variables, comparison = reading.comparison
        if !variables.isEmpty {
            let matching = EnvironmentVariable.matching(filter, in: variables)
            /// Without a comparison, every line shows.
            let lines = showsAll ? matching : matching.filter { comparison?.differs($0) ?? true }
            Divider()
            Label("**Environment**", systemImage: "list.bullet.rectangle")
                .font(.title2)
                .padding(.leading, 5)
            FactsBox {
                header(matching: matching.count)
                if !lines.isEmpty {
                    GroupBox {
                        Text(Self.text(of: lines.prefix(Self.maxLines), comparison: comparison))
                            .font(.body.monospaced())
                            .lineSpacing(3)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if lines.count > Self.maxLines {
                        Text("\((lines.count - Self.maxLines).formatted()) more in the JSON tab.")
                            .foregroundStyle(.secondary)
                    }
                } else if matching.isEmpty {
                    Text("No variables match.").foregroundStyle(.secondary)
                }
                /// With none the same, Show all would add no lines and the footer would read 0 the same.
                if let comparison, comparison.hasSame {
                    footer(comparison)
                }
            }
        }
    }

    /// How many variables there are, or how many the filter matches of them, the comparison's reading, and the filter
    /// field.
    ///
    /// - Parameter matching: How many variables the filter matches.
    /// - Returns: The header.
    private func header(matching: Int) -> some View {
        let count = reading.variables.count
        return HStack {
            Text("\u{2022} **Variables:**")
            FactValue(matching == count ? count.formatted() : "\(matching.formatted()) of \(count.formatted())")
            if let comparison = reading.comparison {
                Text(comparison.reading)
                    .foregroundStyle(.secondary)
                    .help(comparison.help)
            }
            Spacer()
            SettingsSearchField(text: $filter, prompt: "Filter")
                .frame(width: 220)
        }
    }

    /// The link between the differing lines and all of them, and how many are the same when any differ.
    ///
    /// - Parameter comparison: The comparison.
    /// - Returns: The footer.
    private func footer(_ comparison: EnvironmentComparison) -> some View {
        HStack {
            Button(showsAll ? "Show differences only" : "Show all \(reading.variables.count.formatted())") {
                showsAll.toggle()
            }
            .buttonStyle(.link)
            if !comparison.differing.isEmpty {
                Text(comparison.same).foregroundStyle(.secondary)
            }
        }
    }

    /// The lines as one text: each name in the predicate editor's key color, "=" secondary, and the value. A line
    /// that doesn't differ dims its name and draws its value secondary. A variable without "=" is its name alone.
    ///
    /// - Parameters:
    ///   - variables: The variables to draw, in order.
    ///   - comparison: The comparison, or `nil` to dim none.
    /// - Returns: The text, one variable per line.
    private static func text(of variables: ArraySlice<EnvironmentVariable>,
                             comparison: EnvironmentComparison?) -> AttributedString {
        let key = Color(nsColor: PredicateSyntax.keyColor)
        var text = AttributedString()
        for variable in variables {
            let same = comparison.map { !$0.differs(variable) } ?? false
            if variable.id != variables.first?.id {
                text += AttributedString("\n")
            }
            text += escaped(variable.name, color: same ? key.opacity(0.55) : key)
            guard variable.variable != variable.name else { continue }
            text += styled("=", color: .secondary) + escaped(variable.value, color: same ? .secondary : nil)
        }
        return text
    }

    /// The characters drawn as escapes: control characters, and the Unicode line and paragraph separators.
    private static let escapedCategories: Set<Unicode.GeneralCategory> = [.control, .lineSeparator, .paragraphSeparator]

    /// A name or value in its color, with each control character or line break as a secondary escape (`\n`,
    /// `\u{1B}`), so the variable stays on its line. Other characters, backslashes included, draw as stored.
    ///
    /// - Parameters:
    ///   - string: The name or value.
    ///   - color: Its color, or `nil` for the primary one.
    /// - Returns: The text.
    private static func escaped(_ string: String, color: Color?) -> AttributedString {
        var text = AttributedString(), run = ""
        for scalar in string.unicodeScalars {
            guard escapedCategories.contains(scalar.properties.generalCategory) else {
                run.unicodeScalars.append(scalar)
                continue
            }
            text += styled(run, color: color) + styled(scalar.escaped(asASCII: true), color: .secondary)
            run = ""
        }
        return text + styled(run, color: color)
    }

    /// A string in one color.
    ///
    /// - Parameters:
    ///   - string: The string.
    ///   - color: Its color, or `nil` for the primary one.
    /// - Returns: The text.
    private static func styled(_ string: String, color: Color?) -> AttributedString {
        var text = AttributedString(string)
        text.foregroundColor = color
        return text
    }
}


// MARK: - Reading
/// An exec's variables and their comparison with its launcher's, read once for the event: a `StateObject`, so the
/// store isn't looked up again as the filter changes.
private final class EnvironmentReading: ObservableObject {
    /// The exec's variables, in order.
    let variables: [EnvironmentVariable]
    /// The comparison, or `nil` when the store has no launcher's exec.
    let comparison: EnvironmentComparison?

    /// - Parameter message: The exec, in the view context.
    init(message: ESMessage) {
        variables = EnvironmentVariable.variables(in: message.event.exec?.env ?? [])
        comparison = variables.isEmpty ? nil
            : EnvironmentComparison(variables, launcherExec: CoreDataController.shared.launcherExec(of: message))
    }
}
