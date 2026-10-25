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
        for finding in Finding.defaults {
            XCTAssertNil(finding.problem, finding.name)
            XCTAssertTrue(finding.isEnabled && (finding.showsInCorrelation || finding.showsInGroups), finding.name)
            let predicate = try? StreamFilter.Predicate(finding.predicate, for: .finding)
            XCTAssertNotNil(predicate?.storePredicate, "\(finding.name) reads every event's record")
        }
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
            ("AppleScript loaded",
             ["es_event_type": mmap, "target_path": "/System/Library/ScriptingAdditions/StandardAdditions.osax/x"],
             ["es_event_type": mmap, "target_path": "/usr/lib/libSystem.B.dylib"]),
            ("Keychain opened",
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_OPEN",
              "target_path": "/Users/a/Library/Keychains/login.keychain-db"],
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_OPEN", "target_path": "/Users/a/Library/Keychain.txt"]),
            ("New executable", exec([:], ["executable_age_ms": 4]), exec([:], ["executable_age_ms": 400_000])),
            ("Adhoc or unsigned", exec(["codesigning_type": "ADHOC"]), exec(["codesigning_type": "DEVELOPER_ID"])),
            ("Ran a script", exec([:], ["script_content": "echo hi"]), exec([:], ["script_content": ""])),
            ("osascript", exec(["executable": ["name": "osascript"]]), exec(["executable": ["name": "osacompile"]])),
            ("Download tool", exec(["executable": ["name": "curl"]]), exec(["executable": ["name": "curly"]])),
            ("Non-Apple as root", exec(["euid": 0, "codesigning_type": "ADHOC"]),
             exec(["euid": 0, "codesigning_type": "PLATFORM"])),
        ]
        for (name, matching, other) in cases {
            let finding = try XCTUnwrap(Finding.defaults.first { $0.name == name }, name)
            let predicate = try StreamFilter.Predicate(finding.predicate, for: .finding)
            XCTAssertTrue(try predicate.evaluate(on: matching), name)
            XCTAssertFalse(try predicate.evaluate(on: other), name)
        }
    }

    /// The tables are marked for a script and a new executable, as they were before findings marked them, and a
    /// finding saved before ``Finding/showsInTables`` takes the default's choice, or doesn't mark them.
    func testTableMarks() throws {
        XCTAssertEqual(Set(Finding.defaults.filter(\.showsInTables).map(\.name)), ["Ran a script", "New executable"])
        let saved = try JSONEncoder().encode([Finding.defaults[10], Finding(name: "x", explanation: "", symbol: "star",
                                                                             color: .red, predicate: "process.pid == 1",
                                                                             correlation: true, groups: false)])
        var objects = try XCTUnwrap(JSONSerialization.jsonObject(with: saved) as? [[String: Any]])
        for index in objects.indices { objects[index]["showsInTables"] = nil }
        let decoded = try JSONDecoder().decode([Finding].self, from: JSONSerialization.data(withJSONObject: objects))
        XCTAssertEqual(decoded.map(\.showsInTables), [true, false])
        XCTAssertEqual(decoded.first, Finding.defaults[10])
    }

    /// A finding compares one event at a time: a `SUBQUERY` of related events can't be one.
    func testFindingsCompareOneEvent() {
        let finding = Finding(name: "x", explanation: "", symbol: "star", color: .red,
                              predicate: "SUBQUERY(correlated, $e, TRUEPREDICATE).@count > 0",
                              correlation: true, groups: false)
        XCTAssertTrue(finding.problem?.hasPrefix("The finding's predicate can't use SUBQUERY") == true,
                      finding.problem ?? "")
        XCTAssertNil(Finding(name: "x", explanation: "", symbol: "star", color: .red, predicate: "process.pid == 1",
                             correlation: true, groups: false).problem)
    }

    /// Narrowing by the store never leaves a finding out: the matcher agrees with evaluating every finding on every
    /// event of the synthetic corpus and the fixtures.
    func testMatcherAgreesWithEveryPredicate() throws {
        let matcher = FindingMatcher(Finding.defaults)
        let predicates = try Finding.defaults.map { try StreamFilter.Predicate($0.predicate, for: .finding) }
        try withEventStore(try SyntheticCorpus.records().map(\.message) + (try lineageTrace())) { _, stored in
            var found = 0
            for event in stored {
                let record = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(event))
                                           as? NSDictionary)
                let expected = zip(Finding.defaults, predicates)
                    .filter { (try? $0.1.evaluate(on: record)) == true }.map(\.0.id)
                XCTAssertEqual(matcher.matches(event).map(\.id), expected, event.es_event_type ?? "")
                found += expected.count
            }
            XCTAssertGreaterThan(found, 0)
        }
    }
}
