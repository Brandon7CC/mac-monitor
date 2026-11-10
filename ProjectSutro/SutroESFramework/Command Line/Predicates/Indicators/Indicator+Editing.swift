//
//  Indicator+Editing.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Editable fields
public extension Indicator {
    /// The parts of an indicator an edit changes (``IndicatorRequest/Operation/update``), the same for Settings,
    /// `macmonitor indicators edit` and the Security Extension. Whether it's on isn't one: enable and disable change
    /// that, so an edit never undoes another writer's. Nor are the view switches, which are each user's.
    enum EditableField: String, Codable, CaseIterable, Sendable {
        case name, description, symbol, color, predicate, tactic, technique, severity

        /// Is it part of the rule? An edit to one stops a shipped indicator following Mac Monitor's updates, as
        /// ``SavedIndicators`` then saves it in full. Its tactic, technique and severity aren't: an edit to them keeps
        /// it following the rest.
        public var isRule: Bool {
            ![.tactic, .technique, .severity].contains(self)
        }
    }

    /// The editable fields that differ from another indicator's.
    ///
    /// - Parameter other: The indicator after an edit.
    /// - Returns: Those fields, in ``EditableField/allCases`` order. Never whether it's on, nor a view switch.
    func changedFields(to other: Indicator) -> [EditableField] {
        EditableField.allCases.filter { field in
            var mine = self
            mine.take([field], from: other)
            return !mine.isIdentical(to: self)
        }
    }

    /// Is it the same indicator as another, its predicate byte for byte? `String`'s `==`, which this type's is made
    /// of, takes canonically equal spellings as one, where a predicate's `==`, `!=` and `IN` compare bytes: an edit
    /// that only re-spells a constant, NFC to NFD, changes what the indicator matches.
    ///
    /// - Parameter other: Another indicator.
    /// - Returns: Whether they're equal and their predicates are the same UTF-8.
    func isIdentical(to other: Indicator) -> Bool {
        self == other && predicate.utf8.elementsEqual(other.predicate.utf8)
    }

    /// Take some editable fields from another indicator, and keep the rest: identity, switch and views included.
    ///
    /// - Parameters:
    ///   - fields: The fields to take.
    ///   - other: The indicator to take them from.
    mutating func take(_ fields: [EditableField], from other: Indicator) {
        for field in fields {
            switch field {
            case .name: name = other.name
            case .description: description = other.description
            case .symbol: symbol = other.symbol
            case .color: color = other.color
            case .predicate: predicate = other.predicate
            case .tactic: tactic = other.tactic
            case .technique: technique = other.technique
            case .severity: severity = other.severity
            }
        }
    }

    /// Does it detect as another indicator does: every editable field the same, whatever its identity, whether it's
    /// on and its view switches?
    ///
    /// - Parameter other: Another indicator, such as the one Mac Monitor ships with its identity.
    /// - Returns: `true` when ``changedFields(to:)`` is empty.
    func sameDetection(as other: Indicator) -> Bool {
        var mine = self
        mine.id = other.id
        mine.isEnabled = other.isEnabled
        mine.copyViews(from: other)
        return mine == other
    }

    /// Indicators by identity, the first of any that share one.
    ///
    /// - Parameter indicators: The indicators, such as ``defaults``.
    /// - Returns: Each by its identity.
    static func byID(_ indicators: [Indicator]) -> [UUID: Indicator] {
        Dictionary(indicators.map { ($0.id, $0) }) { first, _ in first }
    }
}


// MARK: - Identical sets
public extension Array where Element == Indicator {
    /// Is it the same set as another, each predicate byte for byte (``Indicator/isIdentical(to:)``)? What decides
    /// whether a change saves and compiles anything, or a reply replaces the set shown.
    ///
    /// - Parameter other: Another set.
    /// - Returns: Whether each indicator is identical to the other's in its place.
    func isIdentical(to other: [Indicator]) -> Bool {
        count == other.count && zip(self, other).allSatisfy { $0.isIdentical(to: $1) }
    }
}


// MARK: - Tactics by name
public extension Indicator.Tactic {
    /// The tactic typed on a command line: its raw value (`defenseEvasion`), its ATT&CK identity (`TA0005`) or its
    /// name (`Defense Evasion`), ignoring case, spaces, hyphens and underscores.
    ///
    /// - Parameter text: What was typed.
    /// - Returns: The tactic, or `nil` for none of them.
    static func named(_ text: String) -> Indicator.Tactic? {
        let typed = folded(text)
        guard !typed.isEmpty else { return nil }
        return allCases.first { tactic in
            [tactic.rawValue, tactic.identifier, tactic.name].contains { folded($0) == typed }
        }
    }

    /// - Parameter text: A spelling of a tactic.
    /// - Returns: It in lowercase, without spaces, hyphens or underscores.
    private static func folded(_ text: String) -> String {
        String(text.lowercased().filter { !" -_".contains($0) })
    }
}
