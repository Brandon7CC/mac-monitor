//
//  FindingTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Findings
/// Pins the findings Mac Monitor ships: each one's predicate can be used, narrows by the store, and matches what it
/// says, and the matcher finds exactly what evaluating every finding on every event would.
final class FindingTests: XCTestCase {
    /// Every default can be used, is on, is shown somewhere, and keeps its own identity.
    func testDefaults() {
        XCTAssertEqual(Set(Finding.defaults.map(\.id)).count, Finding.defaults.count)
        XCTAssertEqual(Set(Finding.defaults.map(\.name)).count, Finding.defaults.count)
        for finding in Finding.defaults {
            XCTAssertNil(finding.problem, finding.name)
            XCTAssertTrue(finding.isEnabled && (finding.showsInCorrelation || finding.showsInGroups), finding.name)
            let predicate = try? StreamFilter.Predicate(finding.predicate, for: .finding)
            XCTAssertNotNil(predicate?.storePredicate, "\(finding.name) reads every event's record")
        }
        XCTAssertEqual(Finding.defaults.count, 13)
        XCTAssertEqual(Finding.defaults.first?.id, UUID(uuidString: "6D4D0F1D-0000-4000-8000-000000000001"))
    }

    /// Each default matches a record it's about, and not one that's close.
    func testWhatEachDefaultMatches() throws {
        func exec(_ target: [String: Any], _ exec: [String: Any] = [:]) -> NSDictionary {
            ["es_event_type": "ES_EVENT_TYPE_NOTIFY_EXEC", "event": ["exec": exec.merging(["target": target]) { $1 }]]
        }
        let mmap = "ES_EVENT_TYPE_NOTIFY_MMAP"
        let cases: [(String, NSDictionary, NSDictionary)] = [
            ("Reflective loading",
             ["es_event_type": mmap, "target_path": "/private/var/folders/T/NSCreateObjectFileImageFromMemory-cgAR"],
             ["es_event_type": mmap, "target_path": "/tmp/NSCreateObjectFileImageFromMemory.txt"]),
            ("Not quarantined",
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_CREATE", "process": ["file_quarantine_type": "OPT_IN"],
              "event": ["create": ["is_quarantined": 0]]],
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_CREATE", "process": ["file_quarantine_type": "DISABLED"],
              "event": ["create": ["is_quarantined": 0]]]),
            ("Quarantine removed",
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR",
              "event": ["deleteextattr": ["extattr": "com.apple.quarantine"]]],
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR",
              "event": ["deleteextattr": ["extattr": "com.apple.lastuseddate#PS"]]]),
            ("AppleScript / JXA",
             ["es_event_type": mmap, "target_path": "/System/Library/ScriptingAdditions/StandardAdditions.osax/x"],
             ["es_event_type": mmap, "target_path": "/usr/lib/libSystem.B.dylib"]),
            ("Keychain opened",
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_OPEN",
              "target_path": "/Users/a/Library/Keychains/login.keychain-db"],
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_OPEN", "target_path": "/Users/a/Library/Keychain.txt"]),
            ("New executable", exec([:], ["executable_age_ms": 4]), exec([:], ["executable_age_ms": 1_000])),
            ("Adhoc or unsigned", exec(["codesigning_type": "ADHOC", "signing_id": "a.out"]),
             exec(["codesigning_type": "DEVELOPER_ID", "signing_id": "com.example.app"])),
            ("Ran a script", exec([:], ["script_content": "echo hi"]), exec([:], ["script_content": ""])),
            ("osascript", exec(["executable": ["name": "osascript"]]), exec(["executable": ["name": "osacompile"]])),
            ("Download tool", exec(["executable": ["name": "curl"]]), exec(["executable": ["name": "curly"]])),
        ]
        for (name, matching, other) in cases {
            let finding = try XCTUnwrap(Finding.defaults.first { $0.name == name }, name)
            let predicate = try StreamFilter.Predicate(finding.predicate, for: .finding)
            XCTAssertTrue(try predicate.evaluate(on: matching), name)
            XCTAssertFalse(try predicate.evaluate(on: other), name)
        }
    }

    /// The tables are marked for a script and a new executable.
    func testTableMarks() {
        XCTAssertEqual(Set(Finding.defaults.filter(\.showsInTables).map(\.name)), ["Ran a script", "New executable"])
    }

    /// Saved findings decode one entry at a time. An entry with a color or rendering this build doesn't know is kept
    /// as it was saved and written back after the rest. Data that's neither an object with entries nor an array
    /// decodes to nothing.
    func testSavedFindingsKeepWhatDoesNotDecode() throws {
        let own = Finding(name: "Mine", explanation: "", symbol: "star", color: .red, predicate: "process.pid == 1",
                          correlation: true, groups: false)
        var objects = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(Finding.defaults))
                                    as? [[String: Any]])
        objects[1]["color"] = "mauve"
        objects[3]["rendering"] = "hierarchical"
        objects[5]["symbol"] = nil
        var saved = try XCTUnwrap(SavedFindings(data: JSONSerialization.data(withJSONObject: objects)))
        XCTAssertEqual(saved.findings, Finding.defaults.enumerated().filter { ![1, 3, 5].contains($0.offset) }
            .map(\.element))
        XCTAssertEqual(saved.undecodableCount, 3)
        saved.findings.append(own)
        let written = try XCTUnwrap(saved.encoded())
        let listed = try entries(of: written)
        XCTAssertEqual(listed.count, Finding.defaults.count + 1)
        XCTAssertEqual(listed.suffix(3).map { $0["id"] as? String }, [1, 3, 5].map { objects[$0]["id"] as? String })
        XCTAssertEqual(listed.suffix(3).first?["color"] as? String, "mauve")
        let again = try XCTUnwrap(SavedFindings(data: written))
        XCTAssertEqual(again.findings, saved.findings)
        XCTAssertEqual(again.undecodableCount, 3)
        XCTAssertNil(SavedFindings(data: Data(#"{"findings": []}"#.utf8)))
        XCTAssertEqual(SavedFindings([own]).encoded().flatMap { SavedFindings(data: $0) }?.findings, [own])
    }

    /// A shipped finding nobody edited is saved by identity with its switches, so it follows what an update ships: a
    /// changed rule, a new finding, a dropped one. One turned off stays off.
    func testSavedFindingsFollowShippedFindings() throws {
        var mine = Finding.defaults
        mine[2].isEnabled = false
        let written = try XCTUnwrap(SavedFindings(mine).encoded())
        let listed = try entries(of: written)
        XCTAssertEqual(listed.count, Finding.defaults.count)
        XCTAssertTrue(listed.allSatisfy { $0["default"] is String && $0["predicate"] == nil })
        var update = Finding.defaults
        update[2].predicate += " AND process.pid > 1"
        update.remove(at: 4)
        update.append(Finding(name: "Added", explanation: "", symbol: "star", color: .red,
                              predicate: "process.pid == 2", correlation: true, groups: false))
        var expected = update
        expected[2].isEnabled = false
        XCTAssertEqual(SavedFindings(data: written, defaults: update)?.findings, expected)
    }

    /// An edited shipped finding keeps its edit through an update that changes or drops it, and a deleted one stays
    /// deleted.
    func testSavedFindingsKeepEditsAndDeletions() throws {
        var edited = Finding.defaults[0]
        edited.predicate += " AND process.pid > 1"
        let mine = [edited] + Finding.defaults.dropFirst(2)
        let written = try XCTUnwrap(SavedFindings(mine).encoded())
        var changed = Finding.defaults
        changed[0].explanation = "Changed."
        XCTAssertEqual(SavedFindings(data: written, defaults: changed)?.findings, mine)
        XCTAssertEqual(SavedFindings(data: written, defaults: Array(Finding.defaults.dropFirst()))?.findings, mine)
        XCTAssertEqual(SavedFindings(data: written)?.findings, mine)
    }

    /// Earlier 3.0 builds saved every finding in full. A shipped finding they saved unedited, even an earlier version
    /// of it, follows this build with its switches: the five minute New executable becomes the one second one,
    /// AppleScript loaded becomes AppleScript / JXA, and Non-Apple as root goes. An edited one, someone's own, and a
    /// deletion stay as saved.
    func testEarlierSavedListsFollowShippedFindings() throws {
        let own = Finding(name: "Applet", explanation: "", symbol: "star", color: .red, predicate: "process.pid == 1",
                          correlation: true, groups: false, isEnabled: false)
        var oldAge = try XCTUnwrap(Finding.previousDefaults.first { $0.name == "New executable" })
        oldAge.showsInTables = false
        let oldScript = try XCTUnwrap(Finding.previousDefaults.first { $0.name == "AppleScript loaded" })
        var edited = Finding.defaults[0]
        edited.name = "Mine"
        let earlier = [edited] + Finding.defaults.dropFirst().map { $0.id == oldAge.id ? oldAge : $0 }
            .map { $0.id == oldScript.id ? oldScript : $0 }
            + Finding.previousDefaults.filter { $0.name == "Non-Apple as root" } + [own]
        let saved = try XCTUnwrap(SavedFindings(data: JSONEncoder().encode(earlier)))
        var age = try XCTUnwrap(Finding.defaults.first { $0.id == oldAge.id })
        age.showsInTables = false
        XCTAssertEqual(saved.findings,
                       [edited] + Finding.defaults.dropFirst().map { $0.id == age.id ? age : $0 } + [own])
        XCTAssertTrue(age.predicate.hasSuffix("< 1000"))
        let deleted = try XCTUnwrap(SavedFindings(data: JSONEncoder().encode(Array(Finding.defaults.dropFirst()))))
        XCTAssertEqual(deleted.findings, Array(Finding.defaults.dropFirst()))
    }

    /// Settings ▸ Indicators' search finds a finding by its name, its explanation or its predicate, ignoring case and
    /// accents. Every word has to be found, in any of them. An empty search finds every finding.
    func testSearchMatchesNameExplanationAndPredicate() throws {
        let script = try XCTUnwrap(Finding.defaults.first { $0.name == "AppleScript / JXA" })
        for search in ["applescript", "JXA", "scripting architecture", "javascript.COMPONENT", ".osax", "",
                       "   ", "Opén Scripting", "jxa mmap"] {
            XCTAssertTrue(script.matches(search: search), search)
        }
        for search in ["keychain", "jxa keychain", "XProtect"] {
            XCTAssertFalse(script.matches(search: search), search)
        }
        XCTAssertEqual(Finding.defaults.filter { $0.matches(search: "executable_age_ms") }.map(\.name),
                       ["New executable"])
        XCTAssertEqual(Finding.defaults.filter { $0.matches(search: "") }.count, Finding.defaults.count)
    }

    /// - Parameter data: Saved findings.
    /// - Returns: Their entries.
    private func entries(of data: Data) throws -> [[String: Any]] {
        let saved = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        return try XCTUnwrap(saved["entries"] as? [[String: Any]])
    }

    /// A finding compares one event at a time: a `SUBQUERY` of related events can't be one.
    func testFindingsCompareOneEvent() {
        let finding = Finding(name: "x", explanation: "", symbol: "star", color: .red,
                              predicate: "SUBQUERY(correlated, $e, TRUEPREDICATE).@count > 0",
                              correlation: true, groups: false)
        XCTAssertTrue(finding.problem?.hasPrefix("The indicator's predicate can't use SUBQUERY") == true,
                      finding.problem ?? "")
        XCTAssertNil(Finding(name: "x", explanation: "", symbol: "star", color: .red, predicate: "process.pid == 1",
                             correlation: true, groups: false).problem)
    }

    /// Every default finding and built-in mark is evaluated on the stored event, never on an encoded record. So is a
    /// negation, `ANY` of the environment, and a comparison of two stored key paths. A predicate that matches a
    /// pattern, quantifies another array, or reads a value the store doesn't hold is left to the record.
    func testDefaultsEvaluateOnTheStoredEvent() throws {
        for finding in Finding.defaults + Finding.builtInMarks {
            let predicate = try StreamFilter.Predicate(finding.predicate, for: .finding)
            XCTAssertTrue(StoredEventValues.canEvaluate(predicate.parsed), finding.name)
        }
        for source in [#"NOT (es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC")"#, #"ANY event.exec.env BEGINSWITH "A=""#,
                       "event.exec.target.euid != event.exec.target.ruid"] {
            let predicate = try StreamFilter.Predicate(source, for: .finding)
            XCTAssertTrue(StoredEventValues.canEvaluate(predicate.parsed), source)
        }
        for source in [#"target_path MATCHES ".*x""#, #"ALL event.exec.env BEGINSWITH "A=""#,
                       #"process.executable.path == "/bin/sh""#, #"es_event_type == process.signing_id"#,
                       #"ANY event.exec.args == "-c""#, "event.exec.env == event.exec.env"] {
            let predicate = try StreamFilter.Predicate(source, for: .finding)
            XCTAssertFalse(StoredEventValues.canEvaluate(predicate.parsed), source)
        }
    }

    /// Each key path a finding may read from the stored event holds the record's value there, for every event of the
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

    /// Narrowing by the store never leaves a finding out: the matcher agrees with evaluating every default and built-in
    /// mark on every event of the synthetic corpus and the fixtures.
    func testMatcherAgreesWithEveryPredicate() throws {
        let findings = Finding.defaults + Finding.builtInMarks
        let matcher = FindingMatcher(findings)
        let predicates = try findings.map { try StreamFilter.Predicate($0.predicate, for: .finding) }
        try withEventStore(try SyntheticCorpus.records().map(\.message) + (try lineageTrace())) { _, stored in
            var found = 0
            for event in stored {
                let record = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(event))
                                           as? NSDictionary)
                let expected = zip(findings, predicates)
                    .filter { (try? $0.1.evaluate(on: record)) == true }.map(\.0.id)
                XCTAssertEqual(matcher.matches(event).map(\.id), expected, event.es_event_type ?? "")
                found += expected.count
            }
            XCTAssertGreaterThan(found, 0)
        }
    }

    /// A finding filter reads its predicate from the findings as they are now. A finding that's edited filters by its
    /// new predicate, and one that's off, not in the tables, or unusable is dropped. Any finding's is every offered
    /// finding's joined by `OR`, however long.
    func testFindingSelectionFollowsTheFindings() throws {
        func predicate(_ selection: FindingSelection, _ findings: [Finding]) -> StreamFilter.Predicate? {
            selection.predicate(offered: FindingSelection.offered(findings), for: .search)
        }
        var findings = Finding.defaults
        let index = try XCTUnwrap(findings.firstIndex { $0.name == "Ran a script" })
        let selection = FindingSelection.finding(findings[index].id)
        XCTAssertEqual(predicate(selection, findings)?.source, findings[index].predicate)
        findings[index].predicate = "process.pid == 1"
        XCTAssertEqual(predicate(selection, findings)?.source, "process.pid == 1")
        for change in [{ (finding: inout Finding) in finding.isEnabled = false }, { $0.showsInTables = false },
                       { $0.predicate = "process.nothing == 1" }] {
            var changed = findings
            change(&changed[index])
            XCTAssertNil(predicate(selection, changed))
        }
        XCTAssertNil(predicate(selection, findings.filter { $0.id != findings[index].id }))
        let any = try XCTUnwrap(predicate(.any, findings))
        let offered = FindingSelection.offered(findings)
        XCTAssertEqual(any.source, offered.map { "(\($0.predicate))" }.joined(separator: " OR "))
        XCTAssertEqual(offered.map(\.name), ["New executable", "Ran a script"])
        XCTAssertNil(predicate(.any, []))
        let both = try XCTUnwrap(StreamFilter.Predicate.all([any, try StreamFilter.Predicate("process.pid == 2")],
                                                             for: .search))
        XCTAssertTrue(both.source.hasSuffix(" AND (process.pid == 2)"))
    }
}
