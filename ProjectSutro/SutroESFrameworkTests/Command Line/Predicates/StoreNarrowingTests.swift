//
//  StoreNarrowingTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/25/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - Narrowing a search by the store
/// Pins how a search predicate narrows the events SQLite reads: only by columns that hold the record's own values,
/// only by comparisons SQLite makes as `NSPredicate` does, and never leaving out an event the predicate matches.
final class StoreNarrowingTests: XCTestCase {
    /// Every event type, in each way the synthetic corpus varies them, and the lineage fixture's processes.
    private func messages() throws -> [Message] {
        try SyntheticCorpus.records().map(\.message) + (try lineageTrace())
    }

    /// Each column holds its key path's value whenever the record has one: a column that didn't would leave out events
    /// that match.
    func testColumnsHoldTheRecordsValues() throws {
        try withEventStore(try messages()) { _, stored in
            var checked = 0
            for event in stored {
                let record = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(event))
                                           as? NSDictionary)
                for (path, column) in StoreNarrowing.columns {
                    guard let value = record.value(forKeyPath: path), !(value is NSNull) else { continue }
                    let held = event.value(forKey: column.name) as? NSObject
                    XCTAssertEqual(held, value as? NSObject, "\(event.es_event_type ?? ""): \(path) ↔ \(column.name)")
                    checked += 1
                }
            }
            XCTAssertGreaterThan(checked, 1_000)
        }
    }

    /// Each key path is one a record has.
    func testColumnsAreRecordKeyPaths() {
        for path in StoreNarrowing.columns.keys {
            let keys = path.components(separatedBy: ".")
            XCTAssertEqual(RecordKeyPaths.shared.validCount(of: keys), keys.count, path)
        }
    }

    /// What narrows, to what, and what can't: `!=`, `NOT`, `ANY`, `MATCHES`, a key path no column holds, a constant of
    /// the wrong type, and an `OR` with a part that can't.
    func testWhatNarrows() throws {
        let narrowed = [
            ("process.executable.path ENDSWITH '/curl'", #"initiating_path ENDSWITH "/curl""#),
            ("es_event_type == 'ES_EVENT_TYPE_NOTIFY_EXEC' AND ANY event.exec.args == 'x'",
             #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#),
            ("process.pid > 100 AND context CONTAINS[c] 'keychain'",
             #"initiating_pid > 100 AND context CONTAINS[c] "keychain""#),
            ("es_event_type IN {'ES_EVENT_TYPE_NOTIFY_EXEC', 'ES_EVENT_TYPE_NOTIFY_FORK'}",
             #"es_event_type IN {"ES_EVENT_TYPE_NOTIFY_EXEC", "ES_EVENT_TYPE_NOTIFY_FORK"}"#),
            ("event.exec.target.signing_id BEGINSWITH 'com.apple.' OR process.signing_id == 'x'",
             #"created_signing_id BEGINSWITH "com.apple." OR initiating_signing_id == "x""#),
        ]
        for (source, format) in narrowed {
            let predicate = try StreamFilter.Predicate(source, for: .search)
            XCTAssertEqual(predicate.storePredicate?.predicateFormat, format, source)
        }
        let unnarrowed = [
            "process.executable.path != '/bin/sh'", "NOT process.executable.path ENDSWITH '/sh'",
            "ANY event.exec.args == 'x'", "process.executable.path MATCHES '.*/curl'", "process.team_id == 'X'",
            "process.pid == '1'", "process.pid ENDSWITH '1'",
            "process.executable.path ENDSWITH '/curl' OR process.team_id == 'X'",
            "SUBQUERY(events, $e, $e.es_event_type == 'ES_EVENT_TYPE_NOTIFY_EXEC').@count > 0",
        ]
        for source in unnarrowed {
            XCTAssertNil(try StreamFilter.Predicate(source, for: .search).storePredicate, source)
        }
    }

    /// A `SUBQUERY` collects only from the events its conditions on `$e` alone can be narrowed to, and only when every
    /// `SUBQUERY` can be. What it matches doesn't change.
    func testSubqueriesNarrowTheEventsTheyCollect() throws {
        let narrowed = [
            ("SUBQUERY(correlated, $e, $e.target_path CONTAINS 'x' AND $e.mach_time > mach_time).@count > 0",
             #"target_path CONTAINS "x""#),
            ("SUBQUERY(process_group, $e, $e.es_event_type == 'ES_EVENT_TYPE_NOTIFY_EXEC').@count > 0 OR "
             + "SUBQUERY(events, $e, $e.process.pid == 1).@count > 0",
             #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" OR initiating_pid == 1"#),
        ]
        for (source, format) in narrowed {
            let predicate = try StreamFilter.Predicate(source, for: .search)
            XCTAssertEqual(predicate.relatedStorePredicate?.predicateFormat, format, source)
        }
        let unnarrowed = ["SUBQUERY(events, $e, $e.mach_time > mach_time).@count > 0",
                          "SUBQUERY(correlated, $e, $e.target_path CONTAINS 'x').@count > 0 AND "
                          + "SUBQUERY(events, $e, ANY $e.event.exec.args == 'x').@count > 0"]
        for source in unnarrowed {
            XCTAssertNil(try StreamFilter.Predicate(source, for: .search).relatedStorePredicate, source)
        }

        let container = try makeExportStore(try messages())
        let context = container.newBackgroundContext()
        try context.performAndWait {
            let all = try context.fetch(ESMessage.request())
            let source = "SUBQUERY(process_group, $e, $e.es_event_type == 'ES_EVENT_TYPE_NOTIFY_EXEC').@count > 0"
            let full = try StreamFilter.Predicate(source, for: .search), narrow = full.copy
            try all.forEach(full.collect)
            let collected = try context.fetch(ESMessage.request(where: XCTUnwrap(narrow.relatedStorePredicate)))
            XCTAssertLessThan(collected.count, all.count)
            try collected.forEach(narrow.collect)
            let expected = try all.map { try full.evaluate(on: $0) }
            XCTAssertTrue(expected.contains(true))
            XCTAssertEqual(try all.map { try narrow.evaluate(on: $0) }, expected)
        }
    }

    /// In a store on disk, SQLite's fetch keeps every event the predicate matches.
    func testNarrowingKeepsEveryMatch() throws {
        let container = try makeExportStore(try messages())
        let context = container.newBackgroundContext()
        try context.performAndWait {
            let all = try context.fetch(ESMessage.request())
            let sources = [
                "es_event_type == 'ES_EVENT_TYPE_NOTIFY_EXEC'", "process.pid > 1 AND process.executable.path BEGINSWITH '/'",
                "event.exec.target.executable.path ENDSWITH[c] 'SH' OR event.fork.child.pid > 0",
                "event_type IN {9, 11} AND context CONTAINS 'e'",
            ]
            for source in sources {
                let predicate = try StreamFilter.Predicate(source, for: .search)
                let store = try XCTUnwrap(predicate.storePredicate, source)
                let kept = Set(try context.fetch(ESMessage.request(where: store)).map(\.objectID))
                let matching = try all.filter { try predicate.evaluate(on: $0) }
                XCTAssertFalse(matching.isEmpty, source)
                XCTAssertTrue(matching.allSatisfy { kept.contains($0.objectID) }, source)
            }
        }
    }
}
