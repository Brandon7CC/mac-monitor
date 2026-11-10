//
//  IndicatorLookup.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Indicator indicators by what's typed
/// The Mac's indicators, found by what's typed on the command line: an identity, as `macmonitor indicators list`
/// shows it, or a name, ignoring case. `remove`, `enable` and `disable` act on exactly one indicator per name, so a
/// name two indicators share is refused. `stream --indicator` matches by name, so there it means them all.
struct IndicatorLookup {
    /// The set, in order, as the Security Extension listed it.
    let indicators: [Indicator]

    /// The indicators a reference names: the one with that identity, else those with that name, ignoring case.
    ///
    /// - Parameter reference: An identity or a name, as typed.
    /// - Returns: The indicators, in the set's order. None when no indicator has it.
    func matches(_ reference: String) -> [Indicator] {
        if let id = UUID(uuidString: reference), let found = indicators.first(where: { $0.id == id }) {
            return [found]
        }
        return indicators.filter { $0.name.caseInsensitiveCompare(reference) == .orderedSame }
    }

    /// The one indicator each reference names, each once.
    ///
    /// - Parameter references: Identities or names, as typed.
    /// - Returns: The indicators, in the order first named.
    /// - Throws: ``CommandLineFailure``: 65 for a reference no indicator has, or a name several share.
    func unique(_ references: [String]) throws(CommandLineFailure) -> [Indicator] {
        var found: [Indicator] = []
        for reference in references {
            let matches = matches(reference)
            guard let first = matches.first else { throw unknown(reference) }
            guard matches.count == 1 else {
                let ids = matches.map(\.id.uuidString).joined(separator: ", ")
                throw CommandLineFailure(.dataError, """
                    \(matches.count) indicators are named \(TerminalSafeText.quoted(reference)). Name the one you \
                    mean by its ID: \(ids).
                    """)
            }
            if !found.contains(where: { $0.id == first.id }) { found.append(first) }
        }
        return found
    }

    /// The failure for a reference no indicator has, suggesting the name meant.
    ///
    /// - Parameters:
    ///   - reference: The identity or name, as typed.
    ///   - exit: How `macmonitor` exits: 65 unless given.
    /// - Returns: Such as No indicator has the ID or name “Plist modifed”. Did you mean 'Plist modified'?
    func unknown(_ reference: String, exit: CommandLineExit = .dataError) -> CommandLineFailure {
        let suggestion = CommandLineSuggestion.didYouMean(reference, among: indicators.map(\.name))
        return CommandLineFailure(exit, """
            No indicator has the ID or name \(TerminalSafeText.quoted(reference)).\
            \(TerminalSafeText.text(suggestion)) Run 'macmonitor indicators list' to see them.
            """)
    }
}
