//
//  IndicatorMarks.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Event tables
/// The built-in marks an event matches, and the indicators it matches.
final class EventMarks {
    /// The built-in marks it matches, by identity.
    let builtIn: Set<UUID>
    /// Every indicator that's on it matches, in order: the Indicators popover's.
    let indicators: [Indicator]
    /// Those that mark it with their dot (``Indicator/tableMarks``), in order: its dot's.
    let marked: [Indicator]
    /// Those that mark it with their symbol too, in order.
    let symbols: [Indicator]
    /// The one whose color its label takes (``Indicator/TableMarks/label``): the most severe of those that color it,
    /// as the Indicators popover lists them, or `nil`.
    let labelIndicator: Indicator?

    /// - Parameters:
    ///   - builtIn: The built-in marks it matches.
    ///   - indicators: Every indicator that's on it matches.
    init(builtIn: Set<UUID>, indicators: [Indicator]) {
        self.builtIn = builtIn
        self.indicators = indicators
        marked = indicators.filter { $0.tableMarks.contains(.dot) }
        symbols = indicators.filter { $0.tableMarks.contains(.symbol) }
        labelIndicator = Indicator.bySeverity(indicators.filter { $0.tableMarks.contains(.label) }).first
    }

    /// Its dot in the tables' first column: the highest severity among the indicators that mark it there, whose color
    /// the dot takes, or `nil` when it matches none.
    var dot: IndicatorSeverity? {
        marked.map(\.severity).max()
    }

    /// Its dot's help: the indicator's name and severity, or how many and each one's, the most severe first, six at
    /// most.
    var dotHelp: String {
        let ordered = marked.enumerated().sorted { ($1.element.severity, $0.offset) < ($0.element.severity, $1.offset) }
        let names = ordered.map { "\($0.element.name), \($0.element.severity.name)" }
        guard names.count > 1 else { return names.first ?? "" }
        let more = names.count > 6 ? ["and \(names.count - 6) more"] : []
        return (["\(names.count) indicators"] + names.prefix(6) + more).joined(separator: "\n")
    }

    /// - Parameter marks: Built-in marks, such as ``Indicator/labelMarks``.
    /// - Returns: Those it matches, in their order.
    func matched(_ marks: [Indicator]) -> [Indicator] {
        marks.filter { builtIn.contains($0.id) }
    }

    /// - Parameters:
    ///   - indicator: An indicator that marks it with its symbol.
    ///   - symbol: The symbol the event's label draws, if it's known.
    /// - Returns: Is the label's symbol the indicator's, in the indicator's color? It is when the indicator colors the
    ///   label and has the label's symbol, as Adhoc signed has an exec's seal, so it isn't drawn again before it.
    func isLabelSymbol(_ indicator: Indicator, _ symbol: String?) -> Bool {
        indicator.id == labelIndicator?.id && indicator.symbol == symbol
    }
}


/// An event's indicators that mark it in the tables, before its type or name. Each shows its symbol, with its name and
/// description as help: the first ``limit`` of them, in the order the Mac's set lists them, then how many more there
/// are, which the row's dot lists by name. Settings > Indicators chooses which mark the tables.
struct IndicatorMarks: View {
    /// The most symbols a row draws, so a row stays readable whatever an event matches.
    static let limit = 3

    let message: ESMessage
    /// The built-in marks drawn beside them. An indicator that's a matched mark's twin isn't drawn again.
    var besides: [Indicator] = []
    /// The symbol of the label they're drawn before. The indicator that colors the label isn't drawn again when
    /// that's its symbol too (``EventMarks/isLabelSymbol(_:_:)``).
    var labelSymbol: String?
    @ObservedObject private var store = IndicatorStore.shared

    var body: some View {
        let marks = store.marks(for: message)
        let drawn = Indicator.drawn(marks.symbols, besides: marks.matched(besides))
        let symbols = drawn.filter { !marks.isLabelSymbol($0, labelSymbol) }
        ForEach(symbols.prefix(Self.limit)) { indicator in
            IndicatorSymbol(indicator: indicator).help("\(indicator.name): \(indicator.description)")
        }
        if symbols.count > Self.limit {
            let more = symbols.dropFirst(Self.limit)
            Text("+\(more.count)")
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .help(more.map(\.name).joined(separator: "\n"))
                .accessibilityLabel("\(more.count) more indicators")
        }
    }
}


/// The built-in marks an event matches, as its hard-coded label drew them. Each shows its symbol, with its help.
struct BuiltInMarks: View {
    let message: ESMessage
    /// The marks to look for, in order, such as ``Indicator/labelMarks``.
    let marks: [Indicator]

    var body: some View {
        ForEach(IndicatorStore.shared.marks(for: message).matched(marks)) { mark in
            IndicatorSymbol(indicator: mark)
                .help(ifAny: mark.help(on: message))
        }
    }
}


/// An indicator's symbol, drawn in its one color: every indicator's symbol is monochrome, whatever rendering an older
/// set saved for it. VoiceOver reads its name.
struct IndicatorSymbol: View {
    let indicator: Indicator

    var body: some View {
        Image(systemName: indicator.symbol)
            .foregroundStyle(indicator.tint)
            .accessibilityLabel(indicator.name)
    }
}


// MARK: - Presentation
extension Indicator {
    /// Its color, as SwiftUI draws it. `SwiftUI.Color`: here `Color` is ``Indicator/Color``.
    var tint: SwiftUI.Color { color.swiftUI }

    /// Its card's title.
    ///
    /// - Parameter count: How many events are part of it.
    /// - Returns: Its name, and how many when there's more than one: "Quarantine removed ×3".
    func title(_ count: Int) -> String {
        count > 1 ? "\(name) ×\(count)" : name
    }

    /// A built-in mark's help on an event. It's the mark's description, with the exec's executable age and its
    /// script's path in place of `{age}` and `{script}`.
    ///
    /// - Parameter message: The event.
    /// - Returns: The help.
    func help(on message: ESMessage) -> String {
        guard description.contains("{"), let exec = message.event.exec else { return description }
        return description.replacingOccurrences(of: "{age}", with: exec.executableAgeText ?? "")
            .replacingOccurrences(of: "{script}", with: exec.resolved_script_path ?? "a script")
    }
}


extension View {
    /// - Parameter text: Its help, or "" for none.
    /// - Returns: The view, with the help when there's some.
    @ViewBuilder
    func help(ifAny text: String) -> some View {
        if text.isEmpty {
            self
        } else {
            help(text)
        }
    }
}


extension Indicator.Color {
    /// The color, as SwiftUI draws it.
    var swiftUI: SwiftUI.Color {
        switch self {
        case .red: return .red
        case .orange: return .orange
        case .yellow: return .yellow
        case .green: return .green
        case .teal: return .teal
        case .blue: return .blue
        case .indigo: return .indigo
        case .purple: return .purple
        case .pink: return .pink
        case .gray: return .gray
        case .black: return .black
        case .primary: return .primary
        }
    }
}
