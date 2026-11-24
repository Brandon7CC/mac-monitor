//
//  SessionChains.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - A session's chains
/// One capture session's open chains for each sequence of a set: a ``SequenceTable`` of its own for each, so a
/// session advances its sequences with its own events, once each, whatever Mac Monitor's session or a
/// `macmonitor stream` on the same set sees. A set is shared by every session that follows it, so its chains can't
/// be.
///
/// A session given a new set keeps the table of each sequence that didn't change, its identity and its sequence both
/// the same, so changing the indicators doesn't forget its chains. A set's own chains (``CompiledIndicators/chains``)
/// are what `macmonitor indicators test` and code evaluating a set alone advance.
///
/// **Threading:** immutable once made. Each table locks itself.
public final class SessionChains: @unchecked Sendable {
    /// Mac Monitor's session's budget: ``SequenceTable/totalChains``.
    public static let sessionBudget = SequenceTable.totalChains
    /// A `macmonitor stream`'s budget: a quarter of Mac Monitor's session's, as up to
    /// ``SensorXPC/maxCommandLineStreams`` run beside it.
    public static let streamBudget = SequenceTable.totalChains / 4

    /// Each sequence's table, in the set's order.
    let tables: [SequenceTable]
    /// The most chains each table holds as it's advanced: an even share of the budget.
    let share: Int
    /// Each sequence's identity and sequence, which a session given a new set matches to keep a table.
    private let sequences: [(id: UUID, sequence: IndicatorSequence)]

    /// - Parameters:
    ///   - tables: Each sequence's table, in the set's order.
    ///   - sequences: Its sequences.
    ///   - share: The most chains each table holds.
    init(tables: [SequenceTable], sequences: [CompiledSequence], share: Int) {
        self.tables = tables
        self.sequences = sequences.map { ($0.id, $0.sequence) }
        self.share = share
    }

    /// A session's chains for a set: the previous set's table for each sequence that didn't change, and a new one for
    /// the rest.
    ///
    /// - Parameters:
    ///   - set: The set.
    ///   - previous: The session's chains for the set it had, if any.
    ///   - budget: The most chains the session's sequences hold together.
    public convenience init(for set: CompiledIndicators, reusing previous: SessionChains? = nil,
                            budget: Int = SessionChains.sessionBudget) {
        let tables = set.sequences.map { sequence in
            previous?.table(for: sequence.id, sequence.sequence)
                ?? SequenceTable(sequence.table.program, id: sequence.id)
        }
        self.init(tables: tables, sequences: set.sequences, share: Self.share(of: budget, among: tables.count))
    }

    /// The table this session keeps for a sequence.
    ///
    /// - Parameters:
    ///   - id: Its indicator's identity.
    ///   - sequence: The sequence.
    /// - Returns: The table, or `nil` when the session's set has no such sequence.
    private func table(for id: UUID, _ sequence: IndicatorSequence) -> SequenceTable? {
        sequences.firstIndex { $0.id == id && $0.sequence == sequence }.map { tables[$0] }
    }

    /// An even share of a budget, so the sequences never hold more than it together: at least
    /// ``SequenceTable/minimumChains`` of Mac Monitor's session's, as a set has at most
    /// ``IndicatorLimits/maxIndicators`` indicators, and a quarter of that for a `macmonitor stream`'s.
    ///
    /// - Parameters:
    ///   - budget: The most chains the sequences hold together.
    ///   - count: How many sequences.
    /// - Returns: Each one's share, at least one.
    static func share(of budget: Int, among count: Int) -> Int {
        max(1, budget / max(1, count))
    }

    /// How many chains and early steps its tables hold now, for tests.
    var openChains: Int {
        tables.reduce(0) { $0 + $1.count }
    }
}
