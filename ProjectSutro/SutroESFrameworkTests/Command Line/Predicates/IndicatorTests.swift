//
//  IndicatorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Indicators
/// Pins the indicators Mac Monitor ships: each one's predicate can be used, narrows by the store, and matches what it
/// says, and the matcher finds exactly what evaluating every indicator on every event would.
final class IndicatorTests: XCTestCase {
    /// Every default can be used, is on, is shown somewhere, and keeps its own identity.
    func testDefaults() {
        XCTAssertEqual(Set(Indicator.defaults.map(\.id)).count, Indicator.defaults.count)
        XCTAssertEqual(Set(Indicator.defaults.map(\.name)).count, Indicator.defaults.count)
        for indicator in Indicator.defaults {
            XCTAssertNil(indicator.problem, indicator.name)
            XCTAssertTrue(indicator.isEnabled, indicator.name)
            let predicate = try? StreamFilter.Predicate(indicator.predicate, for: .indicator)
            XCTAssertNotNil(predicate?.storePredicate, "\(indicator.name) reads every event's record")
        }
        XCTAssertEqual(Indicator.defaults.count, 40)
        XCTAssertFalse(Indicator.defaults.contains { ["Not quarantined", "osascript"].contains($0.name) })
        XCTAssertEqual(Indicator.defaults.first?.id, UUID(uuidString: "6D4D0F1D-0000-4000-8000-000000000001"))
    }

    /// Each default matches a record it's about, and not one that's close, and every default has a case.
    func testWhatEachDefaultMatches() throws {
        let cases = defaultCases()
        XCTAssertEqual(Set(cases.map(\.0)), Set(Indicator.defaults.map(\.name)))
        for (name, matching, other) in cases {
            let indicator = try XCTUnwrap(Indicator.defaults.first { $0.name == name }, name)
            let predicate = try StreamFilter.Predicate(indicator.predicate, for: .indicator)
            XCTAssertTrue(try predicate.evaluate(on: matching), name)
            XCTAssertFalse(try predicate.evaluate(on: other), name)
        }
    }

    /// Each built-in mark matches a record it's about, and not one that's close. Every mark has a case, or is a
    /// default's twin, with the default's predicate and so its cases.
    func testWhatEachMarkMatches() throws {
        let cases = markCases()
        let twins = Indicator.builtInMarks.filter { mark in
            Indicator.defaults.contains { $0.id == mark.id && $0.predicate == mark.predicate }
        }
        XCTAssertEqual(twins.map(\.name), ["New executable", "Ran a script", "Dylib inserted"])
        XCTAssertEqual(Set(cases.map(\.0)).union(twins.map(\.name)), Set(Indicator.builtInMarks.map(\.name)))
        for (name, matching, other) in cases {
            let mark = try XCTUnwrap(Indicator.builtInMarks.first { $0.name == name }, name)
            let predicate = try StreamFilter.Predicate(mark.predicate, for: .indicator)
            XCTAssertTrue(try predicate.evaluate(on: matching), name)
            XCTAssertFalse(try predicate.evaluate(on: other), name)
        }
    }

    /// The tables are marked for a script, a new executable, an inserted dylib and a process elevated to root, and for
    /// what colors an event's label too: what the labels colored before indicators could, and adhoc signed and
    /// unsigned code.
    private let labels: Set<String> = [
        "Reflective loading", "Quarantine removed", "Background item added", "XProtect detection", "AppleScript / JXA",
        "Adhoc signed", "Unsigned", "Remote thread created", "Task port retrieved", "Process traced",
        "Code signature invalidated", "HID device opened", "Background item removed", "BTM database modified",
    ]

    func testTableMarks() {
        XCTAssertEqual(Set(Indicator.defaults.filter(\.showsInTables).map(\.name)),
                       Set(["Ran a script", "New executable", "Dylib inserted", "Elevated to root"]).union(labels)
                        .subtracting(["Background item added", "Background item removed"]),
                       "Background items added and removed draw no symbol")
        XCTAssertTrue(Indicator.defaults.allSatisfy { $0.tableMarks.contains(.dot) })
        XCTAssertEqual(Set(Indicator.defaults.filter { $0.tableMarks.contains(.label) }.map(\.name)), labels)
    }

    /// Saved indicators decode one entry at a time. An entry with a color or table mark this build doesn't know is
    /// kept as it was saved and written back after the rest. A key this build doesn't know, such as an earlier build's
    /// `rendering`, is ignored. Data that isn't an object with entries decodes to nothing.
    func testSavedIndicatorsKeepWhatDoesNotDecode() throws {
        let own = Indicator(name: "Mine", description: "", symbol: "star", color: .red, predicate: "process.pid == 1")
        var objects = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(Indicator.defaults))
                                    as? [[String: Any]])
        objects[1]["color"] = "mauve"
        objects[3]["tableMarks"] = "sparkles"
        objects[5]["symbol"] = 7
        objects[6]["rendering"] = "hierarchical"
        let deleted = [1, 3, 5].map { Indicator.defaults[$0].id.uuidString }
        var saved = try XCTUnwrap(SavedIndicators(data: JSONSerialization.data(
            withJSONObject: ["entries": objects, "deleted": deleted])))
        XCTAssertEqual(saved.indicators, Indicator.defaults.enumerated().filter { ![1, 3, 5].contains($0.offset) }
            .map(\.element))
        XCTAssertEqual(saved.undecodableCount, 3)
        saved.indicators.append(own)
        let written = try XCTUnwrap(saved.encoded())
        let listed = try entries(of: written)
        XCTAssertEqual(listed.count, Indicator.defaults.count + 1)
        XCTAssertEqual(listed.suffix(3).map { $0["id"] as? String }, [1, 3, 5].map { objects[$0]["id"] as? String })
        XCTAssertEqual(listed.suffix(3).first?["color"] as? String, "mauve")
        let again = try XCTUnwrap(SavedIndicators(data: written))
        XCTAssertEqual(again.indicators, saved.indicators)
        XCTAssertEqual(again.undecodableCount, 3)
        XCTAssertNil(SavedIndicators(data: Data(#"{"findings": []}"#.utf8)))
        XCTAssertEqual(SavedIndicators([own]).encoded().flatMap { SavedIndicators(data: $0) }?.indicators, [own])
    }

    /// A shipped indicator nobody edited is saved by identity, with only the switches someone changed, so it follows
    /// what an update ships: a changed rule, a changed switch, a new indicator, a dropped one. One turned off stays
    /// off, and one whose table mark someone chose keeps it.
    func testSavedIndicatorsFollowShippedIndicators() throws {
        var mine = Indicator.defaults
        mine[2].isEnabled = false
        mine[3].tableMarks = []
        let written = try XCTUnwrap(SavedIndicators(mine).encoded())
        let listed = try entries(of: written)
        XCTAssertEqual(listed.count, Indicator.defaults.count)
        XCTAssertTrue(listed.allSatisfy { $0["default"] is String && $0["predicate"] == nil })
        XCTAssertEqual(listed.map { Set($0.keys) }[0...3],
                       [["default"], ["default"], ["default", "isEnabled"], ["default", "tableMarks"]])
        var update = Indicator.defaults
        update[2].predicate += " AND process.pid > 1"
        update[1].tableMarks = [.dot, .symbol, .label]
        update[3].tableMarks = [.dot, .symbol, .label]
        update.remove(at: 4)
        update.append(Indicator(name: "Added", description: "", symbol: "star", color: .red,
                                predicate: "process.pid == 2"))
        var expected = update
        expected[2].isEnabled = false
        expected[3].tableMarks = []
        XCTAssertEqual(SavedIndicators(data: written, defaults: update)?.indicators, expected)
    }

    /// An edited shipped indicator keeps its edit through an update that changes or drops it, and a deleted one stays
    /// deleted.
    func testSavedIndicatorsKeepEditsAndDeletions() throws {
        var edited = Indicator.defaults[0]
        edited.predicate += " AND process.pid > 1"
        let mine = [edited] + Indicator.defaults.dropFirst(2)
        let written = try XCTUnwrap(SavedIndicators(mine).encoded())
        var changed = Indicator.defaults
        changed[0].description = "Changed."
        XCTAssertEqual(SavedIndicators(data: written, defaults: changed)?.indicators, mine)
        XCTAssertEqual(SavedIndicators(data: written, defaults: Array(Indicator.defaults.dropFirst()))?.indicators,
                       mine)
        XCTAssertEqual(SavedIndicators(data: written)?.indicators, mine)
    }

    /// A list isn't a saved set: only the object with `entries` that Mac Monitor 3.0 and later write is.
    func testAListIsntASavedSet() throws {
        XCTAssertNil(SavedIndicators(data: try JSONEncoder().encode(Indicator.defaults)))
        XCTAssertNil(SavedIndicators(data: Data("{}".utf8)))
    }

    /// Settings > Indicators' search finds an indicator by its name, its description or its predicate, ignoring case
    /// and accents. Every word has to be found, in any of them. An empty search finds every indicator.
    func testSearchMatchesNameDescriptionAndPredicate() throws {
        let script = try XCTUnwrap(Indicator.defaults.first { $0.name == "AppleScript / JXA" })
        for search in ["applescript", "JXA", "scripting component", "javascript.COMPONENT", ".osax", "",
                       "   ", "Scrípting", "jxa mmap"] {
            XCTAssertTrue(script.matches(search: search), search)
        }
        for search in ["keychain", "jxa keychain", "XProtect"] {
            XCTAssertFalse(script.matches(search: search), search)
        }
        XCTAssertEqual(Indicator.defaults.filter { $0.matches(search: "executable_age_ms") }.map(\.name),
                       ["New executable"])
        XCTAssertEqual(Indicator.defaults.filter { $0.matches(search: "") }.count, Indicator.defaults.count)
    }

    /// - Parameter data: Saved indicators.
    /// - Returns: Their entries.
    private func entries(of data: Data) throws -> [[String: Any]] {
        let saved = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        return try XCTUnwrap(saved["entries"] as? [[String: Any]])
    }

    /// An indicator compares one event at a time: a `SUBQUERY` of related events can't be one.
    func testIndicatorsCompareOneEvent() {
        let indicator = Indicator(name: "x", description: "", symbol: "star", color: .red,
                                  predicate: "SUBQUERY(correlated, $e, TRUEPREDICATE).@count > 0")
        XCTAssertTrue(indicator.problem?.hasPrefix("The indicator's predicate can't use SUBQUERY") == true,
                      indicator.problem ?? "")
        XCTAssertNil(Indicator(name: "x", description: "", symbol: "star", color: .red,
                               predicate: "process.pid == 1").problem)
    }

    /// Every default indicator and built-in mark is evaluated on the stored event, never on an encoded record. So is a
    /// negation, `ANY` of the environment, and a comparison of two stored key paths. A predicate that matches a
    /// pattern, quantifies another array, or reads a value the store doesn't hold is left to the record.
    func testDefaultsEvaluateOnTheStoredEvent() throws {
        for indicator in Indicator.defaults + Indicator.builtInMarks {
            let predicate = try StreamFilter.Predicate(indicator.predicate, for: .indicator)
            XCTAssertTrue(StoredEventValues.canEvaluate(predicate.parsed), indicator.name)
        }
        for source in [#"NOT (es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC")"#, #"ANY event.exec.env BEGINSWITH "A=""#,
                       "event.exec.target.euid != event.exec.target.ruid"] {
            let predicate = try StreamFilter.Predicate(source, for: .indicator)
            XCTAssertTrue(StoredEventValues.canEvaluate(predicate.parsed), source)
        }
        for source in [#"target_path MATCHES ".*x""#, #"ALL event.exec.env BEGINSWITH "A=""#,
                       #"process.tty.path == "/dev/ttys000""#, #"es_event_type == event.exec.target.team_id"#,
                       #"ANY event.exec.args == "-c""#, "event.exec.env == event.exec.env"] {
            let predicate = try StreamFilter.Predicate(source, for: .indicator)
            XCTAssertFalse(StoredEventValues.canEvaluate(predicate.parsed), source)
        }
    }

    /// Each key path an indicator may read from the stored event holds the record's value there, for every event of the
    /// synthetic corpus and the fixtures: `nil` where the record has `null` or nothing, and "" where it has "".
    func testStoredValuesAreTheRecords() throws {
        /// `null` and a missing key read alike.
        func normalized(_ value: Any?) -> NSObject? { value is NSNull ? nil : value as? NSObject }
        try withEventStore(try SyntheticCorpus.records().map(\.message) + (try lineageTrace())) { _, stored in
            var compared = 0
            for event in stored {
                let record = PredicateRecord(try XCTUnwrap(JSONSerialization.jsonObject(
                    with: JSONEncoder().encode(event)) as? NSDictionary))
                for keyPath in StoredEventValues.keyPaths.sorted() {
                    let expected = normalized(record.value(forKeyPath: keyPath))
                    XCTAssertEqual(normalized(StoredEventValues(event).value(forKeyPath: keyPath)), expected,
                                   "\(event.es_event_type ?? "") \(keyPath)")
                    compared += expected == nil ? 0 : 1
                }
            }
            XCTAssertGreaterThan(compared, stored.count * 4)
        }
    }

    /// An indicator filter lists the indicators it shows the events of, by identity, on each record's `indicators`: a
    /// indicator that's edited is still filtered by, and one that's off or unusable is dropped; one that doesn't mark
    /// the tables isn't. Any indicator's lists every offered indicator, however many: every default, as each is on.
    func testIndicatorSelectionFollowsTheIndicators() throws {
        func predicate(_ selection: IndicatorSelection, _ indicators: [Indicator]) -> StreamFilter.Predicate? {
            selection.predicate(offered: IndicatorSelection.offered(indicators), for: .search)
        }
        func listing(_ indicators: [Indicator]) -> String {
            "ANY indicators.id IN {" + indicators.map { "\"\($0.id.uuidString)\"" }.joined(separator: ", ") + "}"
        }
        var indicators = Indicator.defaults
        let index = try XCTUnwrap(indicators.firstIndex { $0.name == "Ran a script" })
        let selection = IndicatorSelection.indicator(indicators[index].id)
        XCTAssertEqual(predicate(selection, indicators)?.source, listing([indicators[index]]))
        indicators[index].predicate = "process.pid == 1"
        XCTAssertEqual(predicate(selection, indicators)?.source, listing([indicators[index]]))
        var unmarked = indicators
        unmarked[index].showsInTables = false
        XCTAssertEqual(predicate(selection, unmarked)?.source, listing([indicators[index]]))
        for change in [{ (indicator: inout Indicator) in indicator.isEnabled = false },
                       { $0.predicate = "process.nothing == 1" }] {
            var changed = indicators
            change(&changed[index])
            XCTAssertNil(predicate(selection, changed))
        }
        XCTAssertNil(predicate(selection, indicators.filter { $0.id != indicators[index].id }))
        let any = try XCTUnwrap(predicate(.any, indicators))
        let offered = IndicatorSelection.offered(indicators)
        XCTAssertEqual(any.source, listing(offered))
        XCTAssertTrue(any.readsIndicators)
        XCTAssertEqual(offered.map(\.name), Indicator.defaults.map(\.name))
        XCTAssertNil(predicate(.any, []))
        let both = try XCTUnwrap(StreamFilter.Predicate.all([any, try StreamFilter.Predicate("process.pid == 2")],
                                                             for: .search))
        XCTAssertTrue(both.source.hasSuffix(" AND (process.pid == 2)"))
    }

    /// Each mark is chosen apart: a label without a symbol, a symbol without a dot, or none. They're written by name,
    /// read back as they were, and turning the symbol on or off (``Indicator/showsInTables``) changes only the symbol.
    func testTableMarksAreChosenApart() throws {
        var indicator = Indicator(name: "Mine", description: "", symbol: "star", color: .red,
                                  predicate: "process.pid == 1", tables: [.dot, .label])
        XCTAssertEqual(try jsonObject(encoding: indicator)["tableMarks"] as? [String], ["dot", "label"])
        XCTAssertNil(try jsonObject(encoding: indicator)["tableMark"])
        XCTAssertFalse(IndicatorScope.symbol.contains(indicator))
        indicator.showsInTables = true
        XCTAssertEqual(indicator.tableMarks, [.dot, .symbol, .label])
        XCTAssertTrue(IndicatorScope.symbol.contains(indicator))
        for marks: Indicator.TableMarks in [[], .symbol, .label, [.symbol, .label], [.dot, .symbol, .label]] {
            indicator.tableMarks = marks
            XCTAssertEqual(try JSONDecoder().decode(Indicator.self, from: JSONEncoder().encode(indicator)), indicator)
        }
        XCTAssertEqual(Indicator.TableMarks([.symbol, .label]).title, "Symbol, Label color")
        XCTAssertEqual(Indicator.TableMarks().title, "Not marked")
    }

    // MARK: Table marks and tactics
    /// An indicator saved before the marks were chosen apart has the one it chose, `tableMark`: a label was the
    /// label, the symbol and the dot, a symbol the symbol and the dot. One saved before that has `showsInTables`: on is
    /// the symbol and the dot, off the dot. A reference to a shipped indicator reads either, and writes only the set.
    func testTableMarksReadEarlierChoices() throws {
        let indicator = Indicator(name: "Mine", description: "", symbol: "star", color: .red,
                                  predicate: "process.pid == 1")
        var object = try jsonObject(encoding: indicator)
        object["tableMarks"] = nil
        let earlier: [(String, Any, Indicator.TableMarks)] = [
            ("tableMark", "label", [.dot, .symbol, .label]), ("tableMark", "symbol", [.dot, .symbol]),
            ("tableMark", "dot", .dot), ("tableMark", "off", []), ("showsInTables", true, [.dot, .symbol]),
            ("showsInTables", false, .dot),
        ]
        for (key, value, marks) in earlier {
            var saved = object
            saved[key] = value
            let data = try JSONSerialization.data(withJSONObject: saved)
            XCTAssertEqual(try JSONDecoder().decode(Indicator.self, from: data).tableMarks, marks, "\(key) \(value)")
        }
        object["tableMark"] = "sparkles"
        let unknown = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try JSONDecoder().decode(Indicator.self, from: unknown))

        var indicators = Indicator.defaults
        indicators[0].tableMarks = .label
        let written = try XCTUnwrap(SavedIndicators(indicators).encoded())
        XCTAssertEqual(try XCTUnwrap(entries(of: written).first)["tableMarks"] as? [String], ["label"])
        XCTAssertEqual(SavedIndicators(data: written)?.indicators, indicators)
        let plist = try XCTUnwrap(Indicator.defaults.first { $0.tableMarks == .dot })
        for (reference, marks) in [(["showsInTables": true], [.dot, .symbol] as Indicator.TableMarks),
                                   (["tableMark": "off"], [])] {
            let legacy = try JSONSerialization.data(withJSONObject: [
                "entries": [reference.merging(["default": plist.id.uuidString]) { $1 }], "deleted": [],
            ])
            XCTAssertEqual(SavedIndicators(data: legacy)?.indicators.first?.tableMarks, marks, "\(reference)")
        }
    }

    /// A shipped indicator's tactic and technique follow the build, unless someone changed them: only a change is saved
    /// in its reference, and none is `null`. Changing them isn't an edit of its rule, so its predicate still follows
    /// the build too.
    func testTacticFollowsTheBuildUnlessChanged() throws {
        var indicators = Indicator.defaults
        XCTAssertEqual(indicators[0].tactic, .defenseEvasion)
        let untouched = try XCTUnwrap(SavedIndicators(indicators).encoded())
        XCTAssertNil(try entries(of: untouched).first?["tactic"])
        var later = Indicator.defaults
        later[0].tactic = .execution
        later[0].predicate += " AND process.pid > 1"
        XCTAssertEqual(SavedIndicators(data: untouched, defaults: later)?.indicators.first, later[0])

        indicators[0].tactic = .persistence
        indicators[1].tactic = nil
        indicators[1].technique = nil
        let changed = try XCTUnwrap(SavedIndicators(indicators).encoded())
        let saved = try entries(of: changed)
        XCTAssertEqual(saved[0]["tactic"] as? String, "persistence")
        XCTAssertNotNil(saved[0]["default"])
        XCTAssertTrue(saved[1]["tactic"] is NSNull && saved[1]["technique"] is NSNull)
        let read = try XCTUnwrap(SavedIndicators(data: changed, defaults: later)?.indicators)
        XCTAssertEqual(read[0].tactic, .persistence)
        XCTAssertEqual(read[0].predicate, later[0].predicate)
        XCTAssertNil(read[1].tactic)
        XCTAssertNil(read[1].technique)
    }

    /// Every default but XProtect detection has a tactic and a technique, and the search finds them by either.
    func testDefaultsHaveTactics() throws {
        for indicator in Indicator.defaults where indicator.name != "XProtect detection" {
            XCTAssertNotNil(indicator.tactic, indicator.name)
            XCTAssertTrue(indicator.technique?.hasPrefix("T1") == true, indicator.name)
        }
        XCTAssertEqual(Indicator.defaults.filter { $0.tactic == .persistence }.count, 10)
        XCTAssertTrue(Indicator.defaults.filter { $0.matches(search: "TA0006") }
            .allSatisfy { $0.tactic == .credentialAccess })
        XCTAssertEqual(Indicator.defaults.filter { $0.matches(search: "T1543.001") }.map(\.name),
                       ["Background item added"])
    }

    /// Any indicator leaves out one the tables don't mark, but it can still be filtered by on its own.
    func testAnyIndicatorLeavesOutUnmarked() throws {
        var indicators = Indicator.defaults
        let index = try XCTUnwrap(indicators.firstIndex { $0.name == "Plist modified" })
        indicators[index].tableMarks = []
        let offered = IndicatorSelection.offered(indicators)
        let any = try XCTUnwrap(IndicatorSelection.any.predicate(offered: offered, for: .search))
        XCTAssertFalse(any.source.contains(indicators[index].id.uuidString))
        let one = IndicatorSelection.indicator(indicators[index].id)
        XCTAssertEqual(one.predicate(offered: offered, for: .search)?.source,
                       #"ANY indicators.id IN {"\#(indicators[index].id.uuidString)"}"#)
    }
}
