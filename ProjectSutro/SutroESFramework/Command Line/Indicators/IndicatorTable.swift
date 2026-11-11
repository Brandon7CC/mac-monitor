//
//  IndicatorTable.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Indicator table
/// The Mac's indicators as `macmonitor indicators list` shows them: one a line, in the set's order, with whether the
/// Security Extension runs it, its severity and its ID, and every name escaped for a terminal. Those it can't run
/// follow, with why.
///
/// ```
/// STATE     SEVERITY   ID                                     NAME
/// on        high       0B4C1F57-6A3D-4C55-9E0B-0B5A3F2E8C11   Launch agent written
/// not run   medium     5D0B8C4E-2F7A-4B1C-8D3E-9A6F1E2C7B40   My indicator
/// ```
public enum IndicatorTable {
    /// The table.
    ///
    /// - Parameters:
    ///   - indicators: The set, in order.
    ///   - problems: The indicators the Security Extension can't run, and why.
    /// - Returns: The text, ending in a newline.
    public static func text(_ indicators: [Indicator], problems: [IndicatorReply.Problem] = []) -> String {
        guard !indicators.isEmpty else { return "This Mac has no indicators.\n" }
        let reasons = Dictionary(problems.map { ($0.id, $0.reason) }) { first, _ in first }
        let rows = [("STATE", "SEVERITY", "ID", "NAME")] + indicators.map { indicator in
            (state(of: indicator, runs: reasons[indicator.id] == nil), indicator.severity.rawValue,
             indicator.id.uuidString, TerminalSafeText.text(indicator.name))
        }
        let widths = [rows.map(\.0.count).max() ?? 0, rows.map(\.1.count).max() ?? 0, rows.map(\.2.count).max() ?? 0]
        let lines = rows.map { row in
            zip([row.0, row.1, row.2], widths).map { $0.padding(toLength: $1, withPad: " ", startingAt: 0) }
                .joined(separator: "   ") + "   " + row.3
        }
        let unrun = indicators.compactMap { indicator in
            reasons[indicator.id].map { "  \(TerminalSafeText.text(indicator.name)): \(TerminalSafeText.text($0))" }
        }
        let footnote = unrun.isEmpty ? [] : ["", "The Security Extension can't run these, so they never match:"]
            + unrun
        return (lines + footnote).joined(separator: "\n") + "\n"
    }

    /// Every detail of indicators, as `macmonitor indicators show` writes them: each one's name, then a fact a
    /// line, with a blank line between indicators.
    ///
    /// ```
    /// New executable
    ///   ID             6D4D0F1D-0000-4000-8000-000000000009
    ///   State          on
    ///   Severity       medium
    ///   Tactic         Execution (TA0002)
    ///   Technique      T1204.002
    ///   Default        yes
    ///   Event tables   Dot, Symbol
    ///   Description    Its executable was created less than a second before it ran, as a dropper's payload is.
    ///   Predicate      es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND event.exec.executable_age_ms < 1000
    /// ```
    ///
    /// - Parameters:
    ///   - indicators: The indicators, in the order to show them.
    ///   - problems: The indicators the Security Extension can't run, and why.
    ///   - defaults: The indicators Mac Monitor ships, by identity.
    /// - Returns: The text, ending in a newline, every value escaped for a terminal.
    public static func details(_ indicators: [Indicator], problems: [IndicatorReply.Problem] = [],
                               defaults: [UUID: Indicator] = CompiledIndicators.shippedDefaults) -> String {
        let reasons = Dictionary(problems.map { ($0.id, $0.reason) }) { first, _ in first }
        return indicators.map { indicator -> String in
            let reason = reasons[indicator.id]
            let original = defaults[indicator.id]
            let isDefault = original.map { indicator.sameDetection(as: $0) ? "yes" : "yes, edited on this Mac" }
            let rows: [(String, String)] = [
                ("ID", indicator.id.uuidString),
                ("State", state(of: indicator, runs: reason == nil) + (reason.map { ": \($0)" } ?? "")),
                ("Severity", indicator.severity.rawValue),
                ("Tactic", indicator.tactic.map { "\($0.name) (\($0.identifier))" } ?? "none"),
                ("Technique", indicator.technique.flatMap { $0.isEmpty ? nil : $0 } ?? "none"),
                ("Default", isDefault ?? "no"),
                ("Event tables", indicator.tableMarks.title),
                ("Description", indicator.description.isEmpty ? "none" : indicator.description),
                ("Predicate", indicator.predicate),
            ]
            let width = rows.map(\.0.count).max() ?? 0
            return ([TerminalSafeText.text(indicator.name)] + rows.map { name, value in
                "  \(name.padding(toLength: width, withPad: " ", startingAt: 0))   \(TerminalSafeText.text(value))"
            }).joined(separator: "\n")
        }.joined(separator: "\n\n") + "\n"
    }

    /// An indicator in a sentence, such as “My indicator” (medium, 5D0B8C4E-2F7A-4B1C-8D3E-9A6F1E2C7B40).
    ///
    /// - Parameter indicator: The indicator.
    /// - Returns: The words.
    public static func describe(_ indicator: Indicator) -> String {
        "\(TerminalSafeText.quoted(indicator.name)) (\(indicator.severity.rawValue), \(indicator.id.uuidString))"
    }

    /// Indicators in a sentence.
    ///
    /// - Parameter indicators: The indicators.
    /// - Returns: Such as “A”, “A” and “B”, or “A”, “B” and “C”, each quoted and escaped.
    static func names(_ indicators: [Indicator]) -> String {
        let names = indicators.map { TerminalSafeText.quoted($0.name) }
        guard names.count > 1, let last = names.last else { return names.joined() }
        return names.dropLast().joined(separator: ", ") + " and " + last
    }

    /// Whether the Security Extension runs an indicator.
    ///
    /// - Parameters:
    ///   - indicator: The indicator.
    ///   - runs: Can the Security Extension run its predicate?
    /// - Returns: "on", "off", or "not run" for one that's on but can't be run.
    private static func state(of indicator: Indicator, runs: Bool) -> String {
        guard indicator.isEnabled else { return "off" }
        return runs ? "on" : "not run"
    }
}
