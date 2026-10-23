//
//  StreamFilterTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/22/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Stream filter
/// Pins which events `macmonitor stream` writes: an option given more than once matches any of its values, different
/// options must all match, a pattern is found anywhere unless it's anchored, and a predicate `NSPredicate` can't parse
/// or evaluate is an error, never a crash.
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

    /// `--signing-id`, `--grep` and `--where` read the record. `--grep` tries each string on its own, at any depth.
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
        filter.predicates = [try StreamFilter.Predicate("process.audit_token.euid == 501"),
                             try StreamFilter.Predicate("ANY event.exec.args CONTAINS[c] 'TOKEN'")]
        XCTAssertTrue(try filter.admits(record: record))
        filter.predicates.removeLast()
        XCTAssertFalse(try filter.admits(record: record))
    }

    /// A predicate only compares the record's values: anything that calls a method, casts to a class, or takes a
    /// variable is refused as it's parsed, and a key path past a value is `nil`, never a method call.
    func testPredicatesOnlyCompareValues() throws {
        let refused = ["FUNCTION(SELF, 'description') == 'x'", "CAST('NSTask', 'Class') != nil",
                       "FUNCTION(CAST('NSTask', 'Class'), 'new') != nil",
                       "SUBQUERY(event.exec.args, $a, $a == 'x').@count > 0",
                       "$x == 1", "event.exec.args[1] == '-c'", "event.exec.args[SIZE] == 3",
                       "TERNARY(process.pid == 1, 'a', 'b') == 'a'", "FUNCTION('x', 'lowercase:') == 'x'",
                       "process.signing_id.release == nil", "process.signing_id.length == nil", "SELF.@class == nil"]
        for source in refused {
            XCTAssertThrowsError(try StreamFilter.Predicate(source), source) { error in
                XCTAssertTrue("\(error)".hasPrefix("--where can't use "), "\(error)")
            }
        }
        let record: NSDictionary = [
            "process": ["pid": 1, "signing_id": "com.apple.ls", "audit_token": ["euid": 0]],
            "event": ["exec": ["args": ["sh", "-c", "id"], "fds": [["fd": 0], ["fd": 3]]]]
        ]
        let matching = ["process.audit_token.euid == 0", "lowercase(process.signing_id) BEGINSWITH 'com.apple'",
                        "event.exec.args.@count == 3", "ANY event.exec.args == 'id'", "ANY event.exec.fds.fd == 3",
                        "process.pid + 1 == 2", "process.@count == 3", "event.exec.fds.fd.@max == 3",
                        "process.signing_id IN {'com.apple.ls', 'x'}", "process.signing_id.signing_id == nil"]
        for source in matching {
            XCTAssertTrue(try StreamFilter.Predicate(source).evaluate(on: record), source)
        }
        XCTAssertThrowsError(try StreamFilter.Predicate("process.signing_di == 'x'")) { error in
            XCTAssertEqual("\(error)", "--where can't use 'process.signing_di': 'signing_di' isn't a key in Mac "
                           + "Monitor's records. Did you mean 'signing_id'? 'macmonitor schema' describes them. Run "
                           + "'macmonitor help stream'.")
        }
    }
    
    /// A predicate `NSPredicate` can't parse is refused. One it can't evaluate on a record throws, naming it.
    func testPredicatesThatCantBeUsed() throws {
        for source in ["process.pid ==", "process.pid == %@", "))"] {
            XCTAssertThrowsError(try StreamFilter.Predicate(source), source) { error in
                XCTAssertTrue("\(error)".hasPrefix("--where can't read '\(source)': "), "\(error)")
            }
        }
        let predicate = try StreamFilter.Predicate("process.pid MATCHES '1.*'")
        XCTAssertThrowsError(try predicate.evaluate(on: ["process": ["pid": 1]])) { error in
            XCTAssertEqual((error as? StreamFilterError)?.predicate, "process.pid MATCHES '1.*'")
        }
        XCTAssertTrue(try predicate.evaluate(on: ["process": ["pid": "12"]]))
        XCTAssertThrowsError(try StreamFilter.Pattern("(", option: "--grep")) { error in
            XCTAssertEqual("\(error)", "--grep needs a regular expression, not '('. Run 'macmonitor help stream'.")
        }
    }
}
