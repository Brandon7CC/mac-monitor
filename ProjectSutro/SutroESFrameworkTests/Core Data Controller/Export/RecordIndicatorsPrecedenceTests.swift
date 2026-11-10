//
//  RecordIndicatorsPrecedenceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Which indicators a record lists
/// Pins the indicators a record lists: the event's stored verdicts first, then those it matches as it's written,
/// tagged `export`, and none when the writer lists none. An encode made for matching never writes stored verdicts, so
/// a rule that names `indicators` never matches off them. The event store keeps them, and Open Trace keeps a trace's.
final class RecordIndicatorsPrecedenceTests: XCTestCase {
    /// The event store keeps an event's verdicts as they came, hits or none, and nothing for an event nothing
    /// evaluated.
    func testStoreKeepsVerdicts() throws {
        let messages = [stamped(IndicatorVerdictsTests.verdicts), stamped(IndicatorVerdicts()), stamped(nil)]
        try withEventStore(messages) { _, stored in
            XCTAssertEqual(stored.map(\.storedIndicators), [IndicatorVerdictsTests.verdicts.hits, [], nil])
            XCTAssertEqual(stored[1].indicatorsData, Data("[]".utf8))
            XCTAssertNil(stored[2].indicatorsData)
        }
    }

    /// A record lists the stored verdicts when the event has them, though the writer's indicators would match it
    /// differently; empty ones list none. Without stored verdicts, it lists the writer's matches, tagged `export`,
    /// with their severities; verdicts that can't be read count as none. A writer with no indicators, as
    /// `macmonitor stream`'s, lists only the verdicts the event carries, and no key for an event without them.
    func testStoredVerdictsComeFirst() throws {
        let every = Self.every
        XCTAssertEqual(try listed(stamped(IndicatorVerdictsTests.verdicts), with: [every]),
                       try IndicatorVerdictsTests.verdicts.hits.map { try jsonObject(encoding: $0) as NSDictionary })
        XCTAssertEqual(try listed(stamped(IndicatorVerdicts()), with: [every]), [])
        let matched = try XCTUnwrap(try listed(stamped(nil), with: [every]))
        XCTAssertEqual(matched.map { $0["name"] as? String }, [every.name])
        XCTAssertEqual(matched.first?["evaluated_by"] as? String, "export")
        XCTAssertEqual(matched.first?["severity"] as? String, "low")
        XCTAssertEqual(matched.first?["default"] as? Bool, false)
        try withEventStore([stamped(IndicatorVerdictsTests.verdicts)]) { _, stored in
            stored[0].indicatorsData = Data("not verdicts".utf8)
            let record = try recordObject(stored[0], with: [every])
            XCTAssertEqual((record["indicators"] as? [NSDictionary])?.map { $0["name"] as? String }, [every.name])
        }
        XCTAssertEqual(try listed(stamped(IndicatorVerdictsTests.verdicts), with: nil),
                       try IndicatorVerdictsTests.verdicts.hits.map { try jsonObject(encoding: $0) as NSDictionary })
        XCTAssertEqual(try listed(stamped(IndicatorVerdicts()), with: nil), [])
        XCTAssertNil(try listed(stamped(nil), with: nil))
    }

    /// A hit matched as the record is written says whether this Mac edited the shipped indicator it's for, as the
    /// Security Extension's do: not for one of the user's own, nor for a shipped one with only its views changed,
    /// and yes for one whose predicate changed.
    func testExportedHitsSayWhetherAShippedIndicatorWasEdited() throws {
        let original = try XCTUnwrap(Indicator.defaults.first)
        var edited = Self.every
        edited.id = original.id
        var viewed = original
        viewed.tableMarks = original.tableMarks.isEmpty ? [.dot, .symbol] : []
        let own = try XCTUnwrap(try listed(stamped(nil), with: [Self.every])?.first)
        XCTAssertEqual([own["default"] as? Bool, own["edited"] as? Bool], [false, false])
        let changed = try XCTUnwrap(try listed(stamped(nil), with: [edited])?.first)
        XCTAssertEqual([changed["default"] as? Bool, changed["edited"] as? Bool], [true, true])
        XCTAssertEqual(IndicatorHit(viewed, against: CompiledIndicators.shippedDefaults, evaluatedBy: .export).edited,
                       false)
    }

    /// An encode made to match an indicator never writes the stored verdicts: a rule that names a stamped
    /// indicator's name matches nothing, as the event tables and Correlation match it, and as the record a predicate
    /// reads has no `indicators`. A search that names `indicators` reads them, as the record does.
    func testMatchingNeverReadsStoredVerdicts() throws {
        let name = IndicatorVerdictsTests.verdicts.hits[0].name
        let reading = Indicator(name: "Reads verdicts", description: "", symbol: "star", color: .red,
                                predicate: #"ANY indicators.name == "\#(name)""#)
        XCTAssertNil(reading.problem)
        try withEventStore([stamped(IndicatorVerdictsTests.verdicts)]) { _, stored in
            XCTAssertEqual(IndicatorMatcher([reading]).matches(stored[0]), [])
            XCTAssertEqual(try listed(stored[0], with: [reading]), try IndicatorVerdictsTests.verdicts.hits.map {
                try jsonObject(encoding: $0) as NSDictionary
            })
            XCTAssertNil(try StreamFilter.Predicate.record(of: stored[0])["indicators"])
            let search = try StreamFilter.Predicate(reading.predicate)
            XCTAssertTrue(try search.searching(indicators: []) { try search.evaluate(on: stored[0]) })
            XCTAssertFalse(try search.evaluate(on: stored[0]))
        }
    }

    /// Open Trace keeps a record's verdicts, the Security Extension's and those matched at export, and exporting the
    /// event again lists them unchanged. A record from Mac Monitor 3.0, whose entries have no severity or evaluator,
    /// keeps none, so its indicators are matched again as it's exported.
    func testOpenTraceKeepsVerdicts() throws {
        let original = stamped(IndicatorVerdictsTests.verdicts)
        let imported = try importRecord(String(decoding: try exportLine(original, with: [Self.every]), as: UTF8.self))
        XCTAssertEqual(imported.indicators, IndicatorVerdictsTests.verdicts)
        XCTAssertEqual(try listed(imported, with: [Self.every]), try listed(original, with: [Self.every]))

        let matched = try importRecord(String(decoding: try exportLine(stamped(nil), with: [Self.every]),
                                              as: UTF8.self))
        XCTAssertEqual(matched.indicators?.hits.map(\.evaluated_by), [.export])
        XCTAssertEqual(matched.indicators?.hits.map(\.severity), [.low])

        var older = try jsonObject(try exportLine(stamped(nil), with: [Self.every]))
        older["indicators"] = (older["indicators"] as? [[String: Any]])?.map {
            $0.filter { $0.key != "severity" && $0.key != "evaluated_by" }
        }
        let reopened = try importRecord(older)
        XCTAssertNil(reopened.indicators)
        XCTAssertEqual(try listed(reopened, with: [Self.every])?.map { $0["evaluated_by"] as? String }, ["export"])
    }

    /// The store keeps the indicators the Security Extension couldn't rule out, and an empty list as none. A record
    /// lists them only beside the stored verdicts, whether the writer lists indicators or only stored verdicts: an
    /// event whose hits are matched as it's written (none stored, or stored ones that can't be read), an encode made
    /// for matching, and a writer that lists no indicators never write the key.
    func testUndeterminedOnlyBesideStoredVerdicts() throws {
        let undetermined = UndeterminedIndicatorsTests.undetermined
        let messages = [stamped(IndicatorVerdicts(), undetermined), stamped(nil, undetermined),
                        stamped(IndicatorVerdicts(), UndeterminedIndicators([])), stamped(IndicatorVerdicts())]
        try withEventStore(messages) { _, stored in
            XCTAssertEqual(stored.map(\.storedUndetermined), [undetermined.entries, undetermined.entries, nil, nil])
            XCTAssertEqual(stored.map(\.recordedUndetermined), [undetermined.entries, nil, nil, nil])
            let expected = try undetermined.entries.map { try jsonObject(encoding: $0) as NSDictionary }
            let record = try recordObject(stored[0], with: [Self.every])
            XCTAssertEqual(record["indicators_undetermined"] as? [NSDictionary], expected)
            XCTAssertNil(try recordObject(stored[1], with: [Self.every])["indicators_undetermined"])
            XCTAssertNil(try StreamFilter.Predicate.record(of: stored[0])["indicators_undetermined"])
            let unlisted = try jsonObject(Data(ProcessHelpers.eventToJSON(value: stored[0]).utf8))
            XCTAssertNil(unlisted["indicators"] ?? unlisted["indicators_undetermined"])
            stored[0].indicatorsData = Data("not verdicts".utf8)
            XCTAssertNil(try recordObject(stored[0], with: [Self.every])["indicators_undetermined"])
        }
        for indicators in [[Self.every], nil] {
            let line = try jsonObject(exportLine(stamped(IndicatorVerdicts(), undetermined), with: indicators))
            XCTAssertEqual((line["indicators_undetermined"] as? [NSDictionary])?.count, 2)
            let matched = try jsonObject(exportLine(stamped(nil, undetermined), with: indicators))
            XCTAssertNil(matched["indicators_undetermined"])
        }
    }

    /// A search that names only `indicators_undetermined` reads it, as the record does, and an encode made for
    /// matching doesn't, so an indicator's predicate never matches off it.
    func testASearchReadsUndetermined() throws {
        let search = try StreamFilter.Predicate(#"ANY indicators_undetermined.reason == "scan_budget""#)
        XCTAssertTrue(search.readsIndicators)
        XCTAssertFalse(try StreamFilter.Predicate(#"process.executable.path == "indicators_x""#).readsIndicators)
        try withEventStore([stamped(IndicatorVerdicts(), UndeterminedIndicatorsTests.undetermined)]) { _, stored in
            XCTAssertTrue(try search.searching(indicators: []) { try search.evaluate(on: stored[0]) })
            XCTAssertFalse(try search.evaluate(on: stored[0]))
        }
    }

    /// A search that names only `indicators_undetermined` reads stored verdicts alone: it never reads the Mac's
    /// indicators or matches them on an event without verdicts, whose record can't list the key. The store narrows
    /// it, exactly, to the events that store undetermined indicators. One that names `indicators` too reads them.
    func testAnUndeterminedSearchReadsOnlyStoredVerdicts() throws {
        let search = try StreamFilter.Predicate(#"ANY indicators_undetermined.reason == "scan_budget""#, for: .search)
        let both = try StreamFilter.Predicate(#"ANY indicators.name == "x" OR ANY indicators_undetermined.name == "y""#,
                                              for: .search)
        XCTAssertFalse(search.readsIndicatorHits)
        XCTAssertTrue(both.readsIndicatorHits)
        var read = 0
        /// The saved indicators, counting each read.
        /// - Returns: An indicator that matches every event.
        func indicators() -> [Indicator] { read += 1; return [Self.every] }
        XCTAssertEqual(search.storePredicate(listing: indicators())?.predicateFormat,
                       "indicatorsUndeterminedData != nil")
        let narrowed = try StreamFilter.Predicate(#"ANY indicators_undetermined.name == "y" AND process.pid == 2"#,
                                                  for: .search).storePredicate(listing: indicators())
        XCTAssertEqual(narrowed?.predicateFormat, "indicatorsUndeterminedData != nil AND initiating_pid == 2")
        let messages = [stamped(IndicatorVerdicts(), UndeterminedIndicatorsTests.undetermined), stamped(nil),
                        stamped(IndicatorVerdicts())]
        try withEventStore(messages) { context, stored in
            let request = ESMessage.request(sortedBy: [NSSortDescriptor(key: "insert_order", ascending: true)])
            request.predicate = search.storePredicate(listing: indicators())
            XCTAssertEqual(try context.fetch(request), [stored[0]])
            let found = try search.searching(indicators: indicators()) {
                try stored.map { try search.evaluate(on: $0) }
            }
            XCTAssertEqual(found, [true, false, false])
            let encoded = try search.searching(indicators: indicators()) {
                try StreamFilter.Predicate.record(of: stored[1])
            }
            XCTAssertNil(encoded["indicators"], "An event without verdicts isn't matched")
            XCTAssertEqual(read, 0)
            let matched = try both.searching(indicators: indicators()) {
                try StreamFilter.Predicate.record(of: stored[1])
            }
            XCTAssertEqual((matched["indicators"] as? [NSDictionary])?.count, 1)
            XCTAssertEqual(read, 1)
        }
    }

    /// Open Trace keeps a record's undetermined indicators, and exporting the event again lists them unchanged.
    func testOpenTraceKeepsUndetermined() throws {
        let original = stamped(IndicatorVerdictsTests.verdicts, UndeterminedIndicatorsTests.undetermined)
        let line = try exportLine(original, with: [Self.every])
        let imported = try importRecord(String(decoding: line, as: UTF8.self))
        XCTAssertEqual(imported.indicators_undetermined, UndeterminedIndicatorsTests.undetermined)
        let again = try jsonObject(exportLine(imported, with: nil))["indicators_undetermined"] as? [NSDictionary]
        XCTAssertEqual(again, try jsonObject(line)["indicators_undetermined"] as? [NSDictionary])
        XCTAssertEqual(again?.count, 2)
    }
}


// MARK: - Helpers
extension RecordIndicatorsPrecedenceTests {
    /// An indicator of someone's own that matches every event, low.
    static let every = Indicator(name: "Every event", description: "", symbol: "star", color: .red,
                                 predicate: "event_type >= 0", severity: .low)

    /// - Parameters:
    ///   - verdicts: The verdicts to stamp, or `nil` for none.
    ///   - undetermined: The undetermined indicators to stamp, or `nil` for none.
    /// - Returns: The synthetic corpus's first event, stamped.
    private func stamped(_ verdicts: IndicatorVerdicts?, _ undetermined: UndeterminedIndicators? = nil) -> Message {
        var message = (try? SyntheticCorpus.records().first?.message)!
        message.indicators = verdicts
        message.indicators_undetermined = undetermined
        return message
    }

    /// - Parameters:
    ///   - message: An event.
    ///   - indicators: The indicators the writer lists, or `nil` for none.
    /// - Returns: Its export record's line.
    /// - Throws: When the event model is missing.
    private func exportLine(_ message: Message, with indicators: [Indicator]?) throws -> Data {
        var line = ExportEncoder(model: try XCTUnwrap(ExportEncoder.model), indicators: indicators).line(for: message)
        line.removeLast()
        return line
    }

    /// - Parameters:
    ///   - message: An event.
    ///   - indicators: The indicators the writer lists, or `nil` for none.
    /// - Returns: The `indicators` its export record lists, or `nil` for no key.
    /// - Throws: When the record isn't a JSON object.
    private func listed(_ message: Message, with indicators: [Indicator]?) throws -> [NSDictionary]? {
        try jsonObject(exportLine(message, with: indicators))["indicators"].map { try XCTUnwrap($0 as? [NSDictionary]) }
    }

    /// - Parameters:
    ///   - event: A stored event, on its context's queue.
    ///   - indicators: The indicators the writer lists.
    /// - Returns: The `indicators` its record lists, or `nil` for no key.
    /// - Throws: When the record isn't a JSON object.
    private func listed(_ event: ESMessage, with indicators: [Indicator]) throws -> [NSDictionary]? {
        try recordObject(event, with: indicators)["indicators"].map { try XCTUnwrap($0 as? [NSDictionary]) }
    }

    /// - Parameters:
    ///   - event: A stored event, on its context's queue.
    ///   - indicators: The indicators the writer lists.
    /// - Returns: Its record, as Export telemetry writes it.
    /// - Throws: When the record isn't a JSON object.
    private func recordObject(_ event: ESMessage, with indicators: [Indicator]) throws -> [String: Any] {
        try jsonObject(Data(RecordIndicators.encoding(with: RecordIndicators(indicators)) {
            ProcessHelpers.eventToJSON(value: event)
        }.utf8))
    }
}
