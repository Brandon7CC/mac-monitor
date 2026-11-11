//
//  StreamCommand+Indicators.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Checking --indicator
/// `macmonitor stream --indicator NAME|ID` writes the events whose records list that indicator, which the Security
/// Extension matched as it captured them. Before the stream starts, each one is checked against the Mac's set, listed
/// on the stream's own connection, so a stream never waits for events no indicator can match: one no indicator has,
/// one that's off, or one the Security Extension can't run stops it with a usage error (64).
///
/// A Security Extension older than 3.1 has no indicators: it cuts the connection off at the list, its records carry
/// no `indicators` key, and the stream stops with ``CommandLineFailure/indicatorsUnanswered`` (69). Without
/// `--indicator`, nothing is listed and such a stream runs, its records without the key.
extension StreamCommand {
    /// Check a stream's `--indicator` values against the Mac's set.
    ///
    /// - Parameters:
    ///   - references: Each `--indicator` value, as typed.
    ///   - timeout: How long to wait for the list.
    ///   - completion: Called once, on any thread: `nil` when every one names an indicator the Security Extension
    ///     runs, else why not.
    func checkIndicators(_ references: [String], timeout: DispatchTimeInterval,
                         completion: @escaping (CommandLineFailure?) -> Void) {
        client.send(IndicatorRequest(.list), timeout: timeout) { result in
            switch result {
            case .failure(let failure):
                completion(.indicators(failure, to: .list))
            case .success(let reply):
                completion(CommandLineFailure.reply(reply) ?? Self.indicatorProblem(references, in: reply))
            }
        }
    }

    /// The first `--indicator` value no event can match.
    ///
    /// - Parameters:
    ///   - references: Each `--indicator` value, as typed.
    ///   - reply: The Security Extension's list of the set.
    /// - Returns: The failure for the first value that names no indicator, or only ones that are off or that the
    ///   Security Extension can't run, or `nil` when each names one it runs.
    static func indicatorProblem(_ references: [String], in reply: IndicatorReply) -> CommandLineFailure? {
        let lookup = IndicatorLookup(indicators: reply.indicators)
        let reasons = Dictionary(reply.problems.map { ($0.id, $0.reason) }) { first, _ in first }
        for reference in references {
            let matches = lookup.matches(reference)
            guard let first = matches.first else { return lookup.unknown(reference, exit: .usage) }
            let on = matches.filter(\.isEnabled)
            guard let running = on.first else {
                return CommandLineFailure(.usage, """
                    \(TerminalSafeText.quoted(first.name)) is off, so no event matches it. Turn it on with \
                    'sudo macmonitor indicators enable \(first.id.uuidString)'.
                    """)
            }
            if on.allSatisfy({ reasons[$0.id] != nil }) {
                return CommandLineFailure(.usage, """
                    The Security Extension can't run \(TerminalSafeText.quoted(running.name)), so no event matches \
                    it. \(TerminalSafeText.text(reasons[running.id] ?? ""))
                    """)
            }
        }
        return nil
    }
}
