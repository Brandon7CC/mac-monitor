//
//  SessionChainsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - A session's chains
/// Pins each capture session's own chains (``SessionChains``): two sessions on one set each complete a chain with
/// their own events, leaving the set's own chains alone, a session given a new set keeps the table of each sequence
/// that didn't change, and a `macmonitor stream` holds a quarter of Mac Monitor's session's budget.
final class SessionChainsTests: XCTestCase {
    /// Two sessions each advance their own chains with the same download and chmod, and each completes one.
    func testEachSessionAdvancesItsOwnChains() throws {
        let indicator = sequenceIndicator(SequenceEngineTests.ordered())
        let compiled = CompiledIndicators([indicator])
        let app = SessionChains(for: compiled)
        let stream = SessionChains(for: compiled, budget: SessionChains.streamBudget)
        let events = try recordedEvents(SequenceEngineTests.download)
        var values = MessageValueCache()
        var tagged: [Bool] = []
        for (event, chains) in [(events[0], app), (events[0], stream), (events[1], app), (events[1], stream)] {
            tagged.append(compiled.evaluate(event, values: &values, chains: chains).hits.contains {
                $0.id == indicator.id
            })
        }
        XCTAssertEqual(tagged, [false, false, true, true])
        XCTAssertEqual(compiled.openChains, 0, "The set's own chains are left alone")
        XCTAssertEqual(app.share, SequenceTable.totalChains)
        XCTAssertEqual(stream.share, SequenceTable.totalChains / 4)
    }

    /// A session given a new set keeps the table of a sequence whose identity and steps are the same, starts over for
    /// one that changed, and never shares the set's own.
    func testASessionKeepsTheChainsOfASequenceThatDidntChange() throws {
        let id = UUID()
        let old = CompiledIndicators([sequenceIndicator(SequenceEngineTests.ordered(), id: id)])
        let chains = SessionChains(for: old)
        let same = CompiledIndicators([sequenceIndicator(SequenceEngineTests.ordered(), id: id)], reusing: old)
        let changed = CompiledIndicators([sequenceIndicator(SequenceEngineTests.ordered(within: 6), id: id)],
                                         reusing: old)
        XCTAssertTrue(SessionChains(for: same, reusing: chains).tables[0] === chains.tables[0])
        XCTAssertFalse(SessionChains(for: changed, reusing: chains).tables[0] === chains.tables[0])
        XCTAssertFalse(chains.tables[0] === old.sequences[0].table, "A session's own, not the set's")
    }
}
