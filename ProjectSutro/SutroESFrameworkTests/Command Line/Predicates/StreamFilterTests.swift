//
//  StreamFilterTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/22/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Stream filter
/// Pins which events `macmonitor stream` writes: an option given more than once matches any of its values, except
/// `--predicate`, whose values must all match. Different options must all match, a pattern is found anywhere unless
/// it's anchored, and a predicate `NSPredicate` can't parse or evaluate is an error, never a crash.
final class StreamFilterTests: XCTestCase {
    /// An exec's header.
    ///
    /// - Parameters:
    ///   - pid: The process.
    ///   - path: Its executable.
    ///   - target: The event's target path.
    /// - Returns: The header.
    private func header(pid: Int32 = 321, path: String? = "/usr/bin/curl",
                        target: String? = "/tmp/a.plist") -> EventHeader {
        EventHeader(sequence: 1, globalSequence: 1, eventType: 9, name: "ES_EVENT_TYPE_NOTIFY_EXEC", time: "",
                    process: EventHeader.Process(pid: pid, groupID: pid, user: "root", path: path), context: nil,
                    targetPath: target)
    }

    /// Patterns, as one option would take them.
    ///
    /// - Parameters:
    ///   - option: The option.
    ///   - sources: The regular expressions.
    /// - Returns: The patterns.
    /// - Throws: ``CommandLineUsageError`` for one that isn't a regular expression.
    private func patterns(_ option: String, _ sources: String...) throws -> [StreamFilter.Pattern] {
        try sources.map { try StreamFilter.Pattern($0, option: option) }
    }

    /// `--pid`, `--process` and `--target` read the header: any value of one option, and every option.
    func testHeaderOptions() throws {
        var filter = StreamFilter()
        XCTAssertTrue(filter.admits(header()))
        filter.processes = try patterns("--process", "wget", "curl$")
        XCTAssertTrue(filter.admits(header()))
        XCTAssertFalse(filter.admits(header(path: "/usr/bin/curly")))
        XCTAssertFalse(filter.admits(header(path: nil)))
        filter.pids = [1, 321]
        XCTAssertTrue(filter.admits(header()))
        XCTAssertFalse(filter.admits(header(pid: 2)))
        filter.targets = try patterns("--target", "(?i)\\.PLIST$")
        XCTAssertTrue(filter.admits(header()))
        XCTAssertFalse(filter.admits(header(target: "/tmp/a.txt")))
        XCTAssertFalse(filter.readsRecords)
    }

    /// `--signing-id`, `--grep` and `--predicate` read the record. `--grep` tries each string on its own, at any depth.
    func testRecordOptions() throws {
        let record: NSDictionary = [
            "process": ["signing_id": "com.apple.curl", "audit_token": ["euid": 0]],
            "event": ["exec": ["args": ["curl", "-H", "Authorization: token"]]]
        ]
        var filter = StreamFilter()
        filter.signingIDs = try patterns("--signing-id", "^com\\.apple\\.")
        XCTAssertTrue(filter.readsRecords)
        XCTAssertTrue(try filter.admits(record: record))
        XCTAssertFalse(try filter.admits(record: ["process": ["signing_id": "org.example.com.apple"]]))
        filter.greps = try patterns("--grep", "nothing", "Authorization")
        XCTAssertTrue(try filter.admits(record: record))
        filter.greps = try patterns("--grep", "^curl -H")
        XCTAssertFalse(try filter.admits(record: record))
        filter.greps = []
        filter.predicates = [try StreamFilter.Predicate("process.audit_token.euid == 0"),
                             try StreamFilter.Predicate("ANY event.exec.args CONTAINS[c] 'TOKEN'")]
        XCTAssertTrue(try filter.admits(record: record))
        filter.predicates[0] = try StreamFilter.Predicate("process.audit_token.euid == 501")
        XCTAssertFalse(try filter.admits(record: record))
    }
    
    /// `--predicate` given more than once must all match, checked in order. One that throws leaves the event
    /// unchecked, unless an earlier one already didn't match, which rejects it.
    func testRepeatedPredicatesMustAllMatch() throws {
        let record: NSDictionary = ["process": ["pid": 1]]
        let (yes, no) = (try StreamFilter.Predicate("process.pid == 1"), try StreamFilter.Predicate("process.pid == 2"))
        let throwing = try StreamFilter.Predicate("process.pid MATCHES '1.*'")
        var filter = StreamFilter()
        let cases = [([yes, yes], true), ([yes, no], false), ([no, yes], false), ([no, throwing], false)]
        for (predicates, admits) in cases {
            filter.predicates = predicates
            XCTAssertEqual(try filter.admits(record: record), admits, "\(predicates.map(\.source))")
        }
        for predicates in [[throwing, no], [yes, throwing], [throwing, yes]] {
            filter.predicates = predicates
            let error = thrown(StreamFilterError.self) { try filter.admits(record: record) }
            XCTAssertEqual(error?.predicate, throwing.source, "\(predicates.map(\.source))")
        }
    }

    /// A predicate only compares the record's values: anything that calls a method, casts to a class, or takes a
    /// variable is refused as it's parsed, and so is a key path past a value, which would only ever be `nil`.
    func testPredicatesOnlyCompareValues() throws {
        let refused = ["FUNCTION(SELF, 'description') == 'x'", "CAST('NSTask', 'Class') != nil",
                       "FUNCTION(CAST('NSTask', 'Class'), 'new') != nil",
                       "SUBQUERY(event.exec.args, $a, $a == 'x').@count > 0",
                       "$x == 1", "event.exec.args[1] == '-c'", "event.exec.args[SIZE] == 3",
                       "TERNARY(process.pid == 1, 'a', 'b') == 'a'", "FUNCTION('x', 'lowercase:') == 'x'",
                       "process.signing_id.release == nil", "process.signing_id.length == nil", "SELF.@class == nil",
                       "process.signing_id.signing_id == nil"]
        for source in refused {
            XCTAssertThrowsError(try StreamFilter.Predicate(source), source) { error in
                XCTAssertTrue("\(error)".hasPrefix("--predicate can't use "), "\(error)")
            }
        }
        let record: NSDictionary = [
            "process": ["pid": 1, "signing_id": "com.apple.ls", "audit_token": ["euid": 0]],
            "event": ["exec": ["args": ["sh", "-c", "id"], "fds": [["fd": 0], ["fd": 3]]]]
        ]
        let matching = ["process.audit_token.euid == 0", "lowercase(process.signing_id) BEGINSWITH 'com.apple'",
                        "event.exec.args.@count == 3", "ANY event.exec.args == 'id'", "ANY event.exec.fds.fd == 3",
                        "process.pid + 1 == 2", "process.@count == 3", "event.exec.fds.fd.@max == 3",
                        "process.signing_id IN {'com.apple.ls', 'x'}"]
        for source in matching {
            XCTAssertTrue(try StreamFilter.Predicate(source).evaluate(on: record), source)
        }
        XCTAssertThrowsError(try StreamFilter.Predicate("process.signing_di == 'x'")) { error in
            XCTAssertEqual("\(error)", "--predicate can't use 'process.signing_di': 'signing_di' isn't a key in Mac "
                           + "Monitor's records. Did you mean 'signing_id'? 'macmonitor schema' describes them. Run "
                           + "'macmonitor help stream'.")
        }
    }
    
    /// A predicate `NSPredicate` can't parse is refused. One it can't evaluate on a record throws, naming it.
    func testPredicatesThatCantBeUsed() throws {
        for source in ["process.pid ==", "process.pid == %@", "))"] {
            XCTAssertThrowsError(try StreamFilter.Predicate(source), source) { error in
                XCTAssertTrue("\(error)".hasPrefix("--predicate can't read '\(source)': "), "\(error)")
            }
        }
        let predicate = try StreamFilter.Predicate("process.pid MATCHES '1.*'")
        let error = thrown(StreamFilterError.self) { try predicate.evaluate(on: ["process": ["pid": 1]]) }
        XCTAssertEqual(error?.predicate, "process.pid MATCHES '1.*'")
        XCTAssertTrue(try predicate.evaluate(on: ["process": ["pid": "12"]]))
        XCTAssertThrowsError(try StreamFilter.Pattern("(", option: "--grep")) { error in
            XCTAssertEqual("\(error)", "--grep needs a regular expression, not '('. Run 'macmonitor help stream'.")
        }
    }
    
    /// The event tables' search checks a predicate on a stored event's record, the JSON Export telemetry writes, and
    /// refuses one in the search field's words.
    func testSearchPredicates() throws {
        try withEventStore([try shellExec()]) { _, stored in
            let sources = [("process.executable.path == '/usr/bin/login'", true), ("process.pid == 401", true),
                           ("process.executable.path ENDSWITH '/curl'", false)]
            for (source, matches) in sources {
                let predicate = try StreamFilter.Predicate(source, for: .search)
                XCTAssertEqual(try predicate.evaluate(on: stored[0]), matches, source)
            }
        }
        XCTAssertThrowsError(try StreamFilter.Predicate("process.signing_di == 'x'", for: .search)) { error in
            XCTAssertEqual((error as? CommandLineUsageError)?.message, "The predicate can't use 'process.signing_di': "
                           + "'signing_di' isn't a key in Mac Monitor's records. Did you mean 'signing_id'? Settings ▸ "
                           + "Telemetry Schema describes them.")
        }
        XCTAssertThrowsError(try StreamFilter.Predicate("))", for: .search)) { error in
            XCTAssertTrue("\(error)".hasPrefix("The predicate can't read '))': "), "\(error)")
        }
    }
    
    /// `MATCHES` matches all of a value, with `[c]`, `ANY` and `NOT`, as `NSPredicate`'s own does, but gives up on a
    /// value that backtracks without end instead of holding up the stream or the search.
    func testMatchesHasATimeLimit() throws {
        let record: NSDictionary = ["process": ["signing_id": "com.apple.ls", "pid": 1],
                                    "event": ["exec": ["args": ["sh", "-c", "id"]]]]
        let matching = ["process.signing_id MATCHES 'com\\.apple\\..*'", "process.signing_id MATCHES[c] 'COM.APPLE.LS'",
                        "ANY event.exec.args MATCHES '-c'", "NOT process.signing_id MATCHES 'apple'",
                        "ALL event.exec.args MATCHES '[-a-z]+'"]
        for source in matching {
            XCTAssertTrue(try StreamFilter.Predicate(source).evaluate(on: record), source)
        }
        XCTAssertFalse(try StreamFilter.Predicate("process.signing_id MATCHES 'apple'").evaluate(on: record))
        XCTAssertThrowsError(try StreamFilter.Predicate("process.signing_id MATCHES 'a)('")) { error in
            XCTAssertTrue("\(error)".contains("its pattern isn't a regular expression"), "\(error)")
        }
        
        let slow = try StreamFilter.Predicate("process.signing_id MATCHES '(a+)+b'")
        let started = Date()
        XCTAssertThrowsError(try slow.evaluate(on: ["process": ["signing_id": String(repeating: "a", count: 64)]])) {
            XCTAssertTrue(($0 as? StreamFilterError)?.reason.hasPrefix("MATCHES gave up on a value") == true, "\($0)")
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
        /// One failure doesn't stick to the next record.
        XCTAssertFalse(try slow.evaluate(on: ["process": ["signing_id": "ab c"]]))
    }
    
    /// An exec of `/tmp/payload` in process group 7, the file its process created, and a write to `/tmp/payload` by a
    /// process in group 9.
    private let relatedRecords: [NSDictionary] = [
        ["global_seq_num": 1, "mach_time": 10, "es_event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
         "process": ["group_id": 7, "session_id": 7, "audit_token_string": "shell"],
         "event": ["exec": ["target": ["group_id": 7, "session_id": 7, "audit_token_string": "payload",
                                       "executable": ["path": "/tmp/payload"]]]]],
        ["global_seq_num": 2, "mach_time": 20, "es_event_type": "ES_EVENT_TYPE_NOTIFY_CREATE",
         "target_path": "/private/var/folders/T/NSCreateObjectFileImageFromMemory-cgARzYvt",
         "process": ["group_id": 7, "session_id": 7, "audit_token_string": "payload"]],
        ["global_seq_num": 3, "mach_time": 30, "es_event_type": "ES_EVENT_TYPE_NOTIFY_WRITE",
         "target_path": "/tmp/payload", "process": ["group_id": 9, "session_id": 9, "audit_token_string": "editor"]],
    ]

    /// Evaluate a search predicate on each of ``relatedRecords``, after collecting them all.
    ///
    /// - Parameter source: The predicate.
    /// - Returns: Whether each matches.
    /// - Throws: Why it can't be parsed or evaluated.
    private func relatedMatches(_ source: String) throws -> [Bool] {
        let predicate = try StreamFilter.Predicate(source, for: .search)
        XCTAssertTrue(predicate.relatesEvents, source)
        try relatedRecords.forEach(predicate.collect)
        return try relatedRecords.map { try predicate.evaluate(on: $0) }
    }

    /// The search compares an event with related ones in a `SUBQUERY`: a plain key path is the searched event's, the
    /// variable's the related event's, and an event is never related to itself. `events` joins events nothing else
    /// relates.
    func testSubqueriesOfRelatedEvents() throws {
        let exec = "es_event_type == 'ES_EVENT_TYPE_NOTIFY_EXEC'"
        let cases: [(String, [Bool])] = [
            ("\(exec) AND SUBQUERY(correlated, $e, $e.target_path CONTAINS 'FromMemory').@count > 0",
             [true, false, false]),
            ("SUBQUERY(process_group, $e, $e.es_event_type == 'ES_EVENT_TYPE_NOTIFY_CREATE').@count > 0",
             [true, false, false]),
            ("SUBQUERY(session_group, $e, TRUEPREDICATE).@count == 1", [true, true, false]),
            ("SUBQUERY(process_events, $e, TRUEPREDICATE).@count == 0", [true, true, true]),
            ("\(exec) AND (SUBQUERY(correlated, $e, $e.es_event_type == 'ES_EVENT_TYPE_NOTIFY_MMAP').@count > 0 "
             + "OR SUBQUERY(process_group, $e, $e.target_path MATCHES '.*FromMemory-.*').@count > 0)",
             [true, false, false]),
            ("SUBQUERY(events, $e, $e.es_event_type == 'ES_EVENT_TYPE_NOTIFY_EXEC' "
             + "AND $e.event.exec.target.executable.path == target_path).@count > 0", [false, false, true]),
            ("SUBQUERY(events, $e, $e.mach_time > mach_time).@count == 2", [true, false, false]),
            ("count(SUBQUERY(events, $e, $e.mach_time < mach_time)) == 2", [false, false, true]),
        ]
        for (source, expected) in cases {
            XCTAssertEqual(try relatedMatches(source), expected, source)
        }
        /// A copy, for another thread, has collected nothing.
        let predicate = try StreamFilter.Predicate("SUBQUERY(events, $e, TRUEPREDICATE).@count > 0", for: .search)
        try relatedRecords.forEach(predicate.collect)
        XCTAssertTrue(try predicate.evaluate(on: relatedRecords[0]))
        XCTAssertFalse(try predicate.copy.evaluate(on: relatedRecords[0]))
    }

    /// A `SUBQUERY` without conditions on both events leaves out exactly the events that are the searched event
    /// (``PredicateRecord/isSame(as:)``): itself, every copy of it, and one whose type is `null` as the searched
    /// event's is; a searched event without a type is left out only as itself.
    func testSubqueriesLeaveOutTheSearchedEvent() throws {
        func event(_ time: Int, _ type: Any) -> NSDictionary {
            ["mach_time": time, "global_seq_num": time, "es_event_type": type]
        }
        let copied = event(1, "ES_EVENT_TYPE_NOTIFY_EXEC"), untyped = event(3, NSNull())
        let kept = [copied, event(1, "ES_EVENT_TYPE_NOTIFY_EXEC"), event(2, "ES_EVENT_TYPE_NOTIFY_EXEC"), untyped,
                    event(3, NSNull()), copied]
        let typeless: NSDictionary = ["mach_time": 1, "global_seq_num": 1]
        let predicates = try (0...kept.count).map {
            try StreamFilter.Predicate("SUBQUERY(events, $e, TRUEPREDICATE).@count == \($0)", for: .search)
        }
        for predicate in predicates { try kept.forEach(predicate.collect) }
        for searched in kept + [typeless, event(4, "ES_EVENT_TYPE_NOTIFY_EXEC")] {
            let expected = kept.filter { !PredicateRecord($0).isSame(as: PredicateRecord(searched)) }.count
            XCTAssertEqual(try predicates.map { try $0.evaluate(on: searched) }.firstIndex(of: true), expected,
                           "\(searched)")
        }
    }

    /// A `SUBQUERY` only goes through related events, its variable only reads key paths the schema names, and the
    /// command line, which has one event at a time, refuses both.
    func testSubqueriesThatCantBeUsed() throws {
        let refused = [
            ("SUBQUERY(event.exec.args, $a, $a == 'x').@count > 0", "a SUBQUERY goes through related events"),
            ("SUBQUERY(events, $e, SUBQUERY(events, $f, TRUEPREDICATE).@count > 0).@count > 0",
             "can't put a SUBQUERY inside another"),
            ("process_group.es_event_type == 'x'", "process_group is related events, compared in a SUBQUERY"),
            ("SUBQUERY(events, $e, $f.target_path == 'x').@count > 0", "can't use $f.target_path"),
            ("SUBQUERY(events, $e, $e.target_path.release == nil).@count > 0", "'release' isn't a key"),
            ("SUBQUERY(events, $e, $e == nil).@count > 0", "can't use $e"),
            ("SUBQUERY(events, $e, TRUEPREDICATE).description == nil", "can't use"),
        ]
        for (source, reason) in refused {
            XCTAssertThrowsError(try StreamFilter.Predicate(source, for: .search), source) { error in
                XCTAssertTrue("\(error)".contains(reason), "\(error)")
            }
        }
        XCTAssertThrowsError(try StreamFilter.Predicate("SUBQUERY(events, $e, TRUEPREDICATE).@count > 0")) { error in
            XCTAssertTrue("\(error)".hasPrefix("--predicate can't use SUBQUERY(events"), "\(error)")
            XCTAssertTrue("\(error)".contains("It compares one event at a time"), "\(error)")
        }
    }

    /// A `SUBQUERY` that picks more than ``RelatedEvents/limit`` events throws, asking for conditions on its variable.
    func testSubqueriesKeepALimitedNumberOfEvents() throws {
        let predicate = try StreamFilter.Predicate("SUBQUERY(events, $e, $e.mach_time < mach_time).@count > 0",
                                                   for: .search)
        for time in 0...RelatedEvents.limit {
            try predicate.collect(["global_seq_num": time, "mach_time": time])
        }
        XCTAssertThrowsError(try predicate.evaluate(on: ["global_seq_num": -1, "mach_time": 5])) {
            XCTAssertTrue(($0 as? StreamFilterError)?.reason.contains("conditions on $e alone") == true, "\($0)")
        }
    }

    /// A predicate longer than ``StreamFilter/Predicate/maxLength`` is refused before it's parsed.
    func testPredicatesHaveAMaximumLength() {
        let long = "process.pid == 1" + String(repeating: " OR process.pid == 1", count: 300)
        XCTAssertEqual(thrown(CommandLineUsageError.self) { try StreamFilter.Predicate(long, for: .search) }?.message,
                       "The predicate can't be longer than 4096 characters.")
    }

    /// ``StreamFilter/Predicate/all(_:for:)`` matches only what every source matches, keeps each source's `OR` to
    /// itself, relates events through any source's `SUBQUERY`, and leaves out blank sources.
    func testAllOfSeveralPredicates() throws {
        XCTAssertNil(try StreamFilter.Predicate.all(["", " \n"], for: .search))
        XCTAssertEqual(try StreamFilter.Predicate.all(["", " process.pid == 1 "], for: .search)?.source,
                       "process.pid == 1")
        let exec = "es_event_type == 'ES_EVENT_TYPE_NOTIFY_EXEC'"
        let both = try XCTUnwrap(StreamFilter.Predicate.all(["process.pid == 1 OR process.pid == 2", exec],
                                                            for: .search))
        XCTAssertEqual(both.source, "(process.pid == 1 OR process.pid == 2) AND (\(exec))")
        let records: [(NSDictionary, Bool)] = [
            (["process": ["pid": 2], "es_event_type": "ES_EVENT_TYPE_NOTIFY_EXEC"], true),
            (["process": ["pid": 2], "es_event_type": "ES_EVENT_TYPE_NOTIFY_FORK"], false),
            (["process": ["pid": 3], "es_event_type": "ES_EVENT_TYPE_NOTIFY_EXEC"], false),
        ]
        for (record, matches) in records {
            XCTAssertEqual(try both.evaluate(on: record), matches, "\(record)")
        }
        let related = try XCTUnwrap(StreamFilter.Predicate.all(
            [exec, "SUBQUERY(correlated, $e, $e.target_path CONTAINS 'FromMemory').@count > 0"], for: .search))
        XCTAssertTrue(related.relatesEvents)
        try relatedRecords.forEach(related.collect)
        XCTAssertEqual(try relatedRecords.map { try related.evaluate(on: $0) }, [true, false, false])
        /// An error names only the source that can't be used.
        let message = thrown(CommandLineUsageError.self) {
            try StreamFilter.Predicate.all(["process.pid == 1", "))"], for: .search)
        }?.message
        XCTAssertTrue(message?.hasPrefix("The predicate can't read '))'") == true, message ?? "")
        /// Two of the longest predicates together are longer than one may be.
        let long = "process.pid == 1" + String(repeating: " OR process.pid == 1", count: 200)
        XCTAssertGreaterThan(long.count * 2, StreamFilter.Predicate.maxLength)
        XCTAssertNotNil(try StreamFilter.Predicate.all([long, long], for: .search)?.copy)
    }
}
