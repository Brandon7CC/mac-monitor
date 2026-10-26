//
//  PredicateTextTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/23/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Predicate text
/// Pins how a predicate is read before it's parsed: every key path a record has, a whole key path checked and the one
/// meant suggested, a boolean key path alone compared to `YES`, and what completes the word being typed.
final class PredicateTextTests: XCTestCase {
    /// The schema's key paths, with an array's objects' keys after the array's path.
    func testKeyPaths() {
        let keyPaths = RecordKeyPaths.shared
        XCTAssertEqual(keyPaths.nodes["event.exec.target.is_adhoc_signed"]?.type, "boolean")
        XCTAssertTrue(keyPaths.nodes["es_event_type"]?.values.contains("ES_EVENT_TYPE_NOTIFY_EXEC") == true)
        XCTAssertTrue(keyPaths.nodes[""]?.children.contains("event") == true)
        XCTAssertEqual(keyPaths.validCount(of: ["process", "@count"]), 2)
        XCTAssertEqual(keyPaths.validCount(of: ["create", "destination"]), 0)
        XCTAssertEqual(keyPaths.validCount(of: ["process", "signing_id", "signing_id"]), 2)
        XCTAssertEqual(keyPaths.suggestion(for: ["create", "destination", "existing_file", "name"]),
                       "event.create.destination.existing_file.name")
    }

    /// A key path whose keys are each a record's, but not where it puts them, is refused with the one meant.
    func testMisplacedKeys() {
        let refused = [
            ("SUBQUERY(correlated, $e, $e.create.destination.existing_file.name ENDSWITH 'x').@count > 0",
             "The predicate can't use '$e.create.destination.existing_file.name': 'create' isn't a key at the top of "
             + "a record. Did you mean '$e.event.create.destination.existing_file.name'? Settings ▸ Telemetry Schema "
             + "describes them."),
            ("process.signing_id.signing_id == nil",
             "The predicate can't use 'process.signing_id.signing_id': 'process.signing_id' has no key 'signing_id'."),
        ]
        for (source, message) in refused {
            XCTAssertThrowsError(try StreamFilter.Predicate(source, for: .search), source) { error in
                XCTAssertTrue("\(error)".hasPrefix(message), "\(error)")
            }
        }
    }

    /// A boolean key path alone is compared to `YES`, wherever it stands alone, and nowhere else.
    func testBooleansAlone() throws {
        let cases = [
            ("event.exec.target.is_adhoc_signed AND process.pid == 1",
             "event.exec.target.is_adhoc_signed == YES AND process.pid == 1"),
            ("NOT process.is_platform_binary", "NOT process.is_platform_binary == YES"),
            ("(process.is_platform_binary || process.pid == 1)",
             "(process.is_platform_binary == YES || process.pid == 1)"),
            ("SUBQUERY(events, $e, $e.process.is_platform_binary).@count > 0",
             "SUBQUERY(events, $e, $e.process.is_platform_binary == YES).@count > 0"),
            ("process.is_platform_binary == NO", "process.is_platform_binary == NO"),
            ("context == 'process.is_platform_binary'", "context == 'process.is_platform_binary'"),
            ("process.pid == 1 AND process.is_platform_binary != event.exec.target.is_adhoc_signed",
             "process.pid == 1 AND process.is_platform_binary != event.exec.target.is_adhoc_signed"),
            ("process.pid == 1AND process.is_platform_binary",
             "process.pid == 1AND process.is_platform_binary == YES"),
        ]
        for (source, compared) in cases {
            XCTAssertEqual(PredicateText.comparingBooleans(source), compared, source)
        }
        let source = "event.exec.target.is_adhoc_signed AND SUBQUERY(correlated, $e, "
            + "$e.event.create.destination.existing_file.name ENDSWITH 'apple.me').@count > 0"
        let predicate = try StreamFilter.Predicate(source, for: .search)
        XCTAssertEqual(predicate.source, source)
        let exec: NSDictionary = ["es_event_type": "ES_EVENT_TYPE_NOTIFY_EXEC", "mach_time": 1, "global_seq_num": 1,
                                  "event": ["exec": ["target": ["is_adhoc_signed": true, "audit_token_string": "a"]]]]
        let create: NSDictionary = ["mach_time": 2, "global_seq_num": 2, "process": ["audit_token_string": "a"],
                                    "event": ["create": ["destination": ["existing_file": ["name": "x.apple.me"]]]]]
        try [exec, create].forEach(predicate.collect)
        XCTAssertTrue(try predicate.evaluate(on: exec))
    }

    /// Tab completes a key path's next key, a variable's key path, a keyword or related events, a key path by its
    /// last key, and inside quotes a value the schema lists.
    func testCompletions() {
        func completions(_ text: String) -> PredicateText.Completion? {
            PredicateText.completions(in: text, at: (text as NSString).length)
        }
        XCTAssertEqual(completions("event.exec.tar")?.words, ["event.exec.target"])
        XCTAssertEqual(completions("process.pid == 1 AND event.exec.tar")?.range, NSRange(location: 21, length: 14))
        XCTAssertTrue(completions("event.exec.")?.words.contains("event.exec.target") == true)
        XCTAssertTrue(completions("SUBQUERY(correlated, $e, $e.proc")?.words.contains("$e.process") == true)
        XCTAssertTrue(completions("SUBQ")?.words.contains("SUBQUERY") == true)
        XCTAssertTrue(completions("corr")?.words.contains("correlated") == true)
        XCTAssertTrue(completions("is_adhoc")?.words.contains("event.exec.target.is_adhoc_signed") == true)
        let quoted = completions(#"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXE"#)
        XCTAssertEqual(quoted?.words.first, "ES_EVENT_TYPE_NOTIFY_EXEC")
        XCTAssertEqual(quoted?.range.location, 18)
        XCTAssertNil(completions("process.pid == "))
        XCTAssertNil(completions(#"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#))
        XCTAssertNil(completions("nothing.like.this"))
    }
}
