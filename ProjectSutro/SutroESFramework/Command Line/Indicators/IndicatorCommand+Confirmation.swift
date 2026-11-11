//
//  IndicatorCommand+Confirmation.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Asking first
/// `macmonitor indicators import` grows or replaces the set the Security Extension runs for Mac Monitor and every
/// stream, for every user, and `edit --file` changes an indicator in it as a file says, so before either does, it
/// lists the set, says what the change would do to it, Mac Monitor's own indicators it would remove, turn off or
/// replace among them, and asks. A change to nothing isn't asked about, unless the Security Extension has a notice
/// about the set, which is said first. `--yes` skips the question. Without a terminal to ask at, it's required.
extension IndicatorCommand {
    /// A change asked about first.
    struct PendingChange {
        /// The command, such as "indicators import", for the message when there's no one to ask.
        let command: String
        /// What it changes, such as "the indicators", for the message when there's no one to ask.
        var changing = "the indicators"
        /// The question, such as "Replace this Mac's indicators with the 3 from “mine.json”?"
        let question: String
        /// What the set becomes, from what it is now.
        let result: ([Indicator]) -> [Indicator]

        /// `indicators import`: the set becomes a file's indicators, or (without `--replace`) gains them, each
        /// replacing the indicator with its identity.
        ///
        /// - Parameters:
        ///   - imported: The file's indicators.
        ///   - source: Where they came from, such as “mine.json” or "standard input".
        ///   - replacing: Make the set exactly them, rather than add them to it.
        /// - Returns: The change.
        static func importing(_ imported: [Indicator], from source: String, replacing: Bool) -> PendingChange {
            let count = String.counted(imported.count, "indicator")
            guard !replacing else {
                return PendingChange(command: "indicators import",
                                     question: "Replace this Mac's indicators with the \(count) from \(source)?") {
                    _ in imported
                }
            }
            return PendingChange(command: "indicators import", question: """
                Add the \(count) from \(source) to this Mac's indicators? Each replaces the indicator with its ID.
                """) { IndicatorExchange.merge(imported, into: $0).indicators }
        }

        /// `indicators edit --file`: one indicator takes the fields the file changes.
        ///
        /// - Parameters:
        ///   - target: The indicator, as the set has it.
        ///   - edited: It, edited.
        ///   - fields: The fields the edit changes, in ``Indicator/EditableField/allCases`` order.
        ///   - source: Where they came from, such as “one.json” or "standard input".
        /// - Returns: The change.
        static func editing(_ target: Indicator, to edited: Indicator, fields: [Indicator.EditableField],
                            from source: String) -> PendingChange {
            let names = fields.map(\.rawValue)
            let listed = names.count > 1 ? names.dropLast().joined(separator: ", ") + " and " + (names.last ?? "")
                : names.joined()
            return PendingChange(command: "indicators edit", changing: "the indicator", question: """
                Change \(TerminalSafeText.quoted(target.name))'s \(listed) from \(source)?
                """) { current in
                current.map { indicator in
                    guard indicator.id == edited.id else { return indicator }
                    var indicator = indicator
                    indicator.take(fields, from: edited)
                    return indicator
                }
            }
        }
    }

    /// Waits for answers, off the connection's queue: a person can take a while.
    static let askingQueue = DispatchQueue(label: "com.swiftlydetecting.agent.cli.indicators.confirm")

    /// Who a change reaches, and the question.
    static let reach = "Mac Monitor and every stream apply it right away, for every user. Continue?"

    /// Ask about a change, then make it.
    ///
    /// - Parameters:
    ///   - change: The change.
    ///   - send: Makes the change.
    ///   - completion: Called once, on any thread, if the change isn't made: the set couldn't be listed, the answer
    ///     was no (exit 1), or there was no one to ask (exit 64).
    func ask(about change: PendingChange, then send: @escaping () -> Void,
             otherwise completion: @escaping (Result<Void, CommandLineFailure>) -> Void) {
        listing(completion) { [self] reply in
            let effect = IndicatorSetChange(from: reply.indicators, to: change.result(reply.indicators))
            /// A notice means the set applied isn't the one saved, so the change matters whatever the numbers say.
            if effect.isEmpty && reply.notice == nil { return send() }
            let question = [change.question, effect.isEmpty ? nil : effect.description, Self.reach].compactMap { $0 }
            Self.askingQueue.async { [self] in
                switch confirm(question.joined(separator: "\n")) {
                case true?: send()
                case false?: completion(.failure(.declined))
                case nil: completion(.failure(.unconfirmed(change.command, changing: change.changing)))
                }
            }
        }
    }
}


// MARK: - What a change does
/// What a change does to the Mac's indicators, indicator by indicator (by identity), for the question
/// `indicators import` asks: how many it adds, removes and changes, and which of Mac Monitor's own it removes, turns
/// off or replaces with another rule.
struct IndicatorSetChange: Equatable, CustomStringConvertible {
    /// Indicators with identities the set doesn't have.
    let added: Int
    /// Indicators the set loses.
    let removed: Int
    /// Indicators whose identity stays and something else changes.
    let changed: Int
    /// How many indicators the set has now.
    let before: Int
    /// How many it has after.
    let after: Int
    /// The names of Mac Monitor's own indicators it removes.
    let shippedRemoved: [String]
    /// The names of Mac Monitor's own indicators it turns off.
    let shippedTurnedOff: [String]
    /// The names of Mac Monitor's own indicators whose rule it changes.
    let shippedReplaced: [String]

    /// How many names a sentence lists before "and 3 more".
    static let namesListed = 3

    /// - Parameters:
    ///   - current: The set now.
    ///   - next: The set after the change.
    ///   - shipped: The identities of Mac Monitor's own indicators.
    init(from current: [Indicator], to next: [Indicator], shipped: Set<UUID> = Set(Indicator.defaults.map(\.id))) {
        let nextByID = Dictionary(next.map { ($0.id, $0) }) { _, last in last }
        let currentIDs = Set(current.map(\.id))
        added = Set(next.map(\.id)).subtracting(currentIDs).count
        removed = current.filter { nextByID[$0.id] == nil }.count
        changed = current.filter { indicator in nextByID[indicator.id].map { $0 != indicator } ?? false }.count
        before = current.count
        after = next.count
        let own = current.filter { shipped.contains($0.id) }
        shippedRemoved = own.filter { nextByID[$0.id] == nil }.map(\.name)
        shippedTurnedOff = own.filter { $0.isEnabled && nextByID[$0.id]?.isEnabled == false }.map(\.name)
        shippedReplaced = own.filter { indicator in
            nextByID[indicator.id].map { !$0.hasSameRule(as: indicator) } ?? false
        }.map(\.name)
    }

    /// Does the change change nothing?
    var isEmpty: Bool {
        added == 0 && removed == 0 && changed == 0
    }

    /// Such as "It adds 1 indicator, removes 27 and changes 0: 27 indicators now, 1 after." and, on the next line,
    /// what it does to Mac Monitor's own: "Of Mac Monitor's own indicators, it removes 27 (“A”, “B”, “C” and 24 more)."
    var description: String {
        let counts = "It adds \(String.counted(added, "indicator")), removes \(removed) and changes \(changed): "
            + "\(String.counted(before, "indicator")) now, \(after) after."
        let parts = [("removes", shippedRemoved), ("turns off", shippedTurnedOff), ("replaces", shippedReplaced)]
            .filter { !$0.1.isEmpty }.map { "\($0.0) \($0.1.count) (\(Self.listing($0.1)))" }
        guard let last = parts.last else { return counts }
        let own = parts.count == 1 ? last : parts.dropLast().joined(separator: ", ") + " and " + last
        return counts + "\nOf Mac Monitor's own indicators, it \(own)."
    }

    /// Names in a sentence, each quoted and escaped, the first few only.
    ///
    /// - Parameter names: The names.
    /// - Returns: Such as “A”, “B”, “C” and 24 more.
    static func listing(_ names: [String]) -> String {
        let quoted = names.prefix(namesListed).map(TerminalSafeText.quoted)
        let rest = names.count - quoted.count
        if rest > 0 { return quoted.joined(separator: ", ") + " and \(rest) more" }
        guard quoted.count > 1, let last = quoted.last else { return quoted.joined() }
        return quoted.dropLast().joined(separator: ", ") + " and " + last
    }
}
