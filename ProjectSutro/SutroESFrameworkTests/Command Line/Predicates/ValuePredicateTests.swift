//
//  ValuePredicateTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - A value's predicate
/// Pins ``ValuePredicate``: each kind of value's predicate in Mac Monitor's literal syntax, strings that survive being
/// quoted, keys that are `NSPredicate`'s own words, that the predicate of every value of every synthetic event's
/// record passes the predicate checks and matches the record it came from, and an event type's predicate, which for a
/// network flow is its event's key.
final class ValuePredicateTests: XCTestCase {
    /// - Parameter text: A record's JSON.
    /// - Returns: The predicate of each of its values, in order, `nil` for the record itself.
    private func predicates(_ text: String) -> [String?] {
        let outline = JSONOutline(text)
        return outline.values.indices.map { ValuePredicate.predicate(for: $0, in: outline, text: text as NSString) }
    }

    /// - Parameter text: A record's JSON.
    /// - Returns: The record, as a predicate is evaluated on it.
    private func record(_ text: String) throws -> NSDictionary {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? NSDictionary)
    }

    /// A string, number, Boolean or `null` is compared, with `ANY` in an array, and an object or array is tested for
    /// being there. Each predicate is one the search takes, and it matches the record.
    func testEachKind() throws {
        let text = """
            {"process": {"pid": 12, "is_platform_binary": false, "signing_id": "com.apple.x", "team_id": null},
             "event": {"exec": {"args": ["/bin/zsh", "-c"], "fds": [{"fd": 3, "fdtype": 1}]},
                       "mprotect": {"size": 4096, "flags": ["VM_PROT_READ"]}}}
            """
        let expected: [String?] = [
            nil, "process != nil", "process.pid == 12", "process.is_platform_binary == NO",
            #"process.signing_id == "com.apple.x""#, "process.team_id == nil", "event != nil", "event.exec != nil",
            "event.exec.args != nil", #"ANY event.exec.args == "/bin/zsh""#, #"ANY event.exec.args == "-c""#,
            "event.exec.fds != nil", "event.exec.fds != nil", "ANY event.exec.fds.fd == 3",
            "ANY event.exec.fds.fdtype == 1", "event.mprotect != nil", "event.mprotect.#size == 4096",
            "event.mprotect.flags != nil", #"ANY event.mprotect.flags == "VM_PROT_READ""#,
        ]
        XCTAssertEqual(predicates(text), expected)
        let record = try record(text)
        for source in expected.compactMap({ $0 }) {
            XCTAssertTrue(try StreamFilter.Predicate(source, for: .search).evaluate(on: record), source)
        }
        XCTAssertFalse(try StreamFilter.Predicate("process.pid == 13", for: .search).evaluate(on: record))
        XCTAssertEqual(predicates(#"{"process": {"is_platform_binary": true}}"#).last,
                       "process.is_platform_binary == YES")
    }

    /// Keys that are `NSPredicate`'s words, in any case, are escaped with `#`, and other keys aren't.
    func testReservedKeys() {
        XCTAssertEqual(ValuePredicate.keyPath("event.mprotect.size"), "event.mprotect.#size")
        XCTAssertEqual(ValuePredicate.keyPath("a.In.b.contains.sizes"), "a.#In.b.#contains.sizes")
        XCTAssertEqual(ValuePredicate.keyPath("process.signing_id"), "process.signing_id")
    }

    /// Strings with quotes, backslashes, control characters, format specifiers, variables, brackets and every kind of
    /// Unicode come back from a predicate's literal as they went in.
    func testStringLiterals() throws {
        let strings = ["plain", #"with "quotes" in"#, #"back\slash"#, "trailing\\", "line\nfeed", "tab\tand\rreturn",
                       "\u{01}control\u{1F}\u{7F}\u{85}", "%@ %K %d %%", "$e.process and $variable", "'single' quotes",
                       "brackets {[()]} ANY == nil", "é and e\u{301}", "😀 👩‍👩‍👧", "", " spaced "]
        for string in strings {
            let literal = IndicatorValue.literal(string[...])
            let source = "process.signing_id == \(literal)"
            let matches = try StreamFilter.Predicate(source, for: .search)
            XCTAssertTrue(try matches.evaluate(on: ["process": ["signing_id": string]]), literal)
            XCTAssertFalse(try matches.evaluate(on: ["process": ["signing_id": string + "x"]]), literal)
        }
        XCTAssertEqual(IndicatorValue.literal(#"a"b\c"#), #""a\"b\\c""#)
        XCTAssertEqual(IndicatorValue.literal("\n\u{01}\u{85}"), #""\n\u0001\u0085""#)
    }

    /// The predicate of every value with a key path, in every synthetic event's record as the JSON tab shows it,
    /// passes the search's checks and `macmonitor stream --predicate`'s, and matches the record.
    func testEveryRecordValueMatchesItsRecord() throws {
        let encoder = ExportEncoder(model: try XCTUnwrap(ExportEncoder.model), pretty: true)
        var checked = 0, long = 0
        var kinds: Set<String> = []
        for record in try SyntheticCorpus.records() {
            let text = String(decoding: encoder.line(for: record.message), as: UTF8.self)
            encoder.reset()
            let values = try self.record(text)
            let outline = JSONOutline(text)
            for index in outline.values.indices {
                guard let source = ValuePredicate.predicate(for: index, in: outline, text: text as NSString) else {
                    XCTAssertTrue(outline.values[index].keyPath.isEmpty, record.label)
                    continue
                }
                guard source.count <= StreamFilter.Predicate.maxLength else {
                    long += 1
                    continue
                }
                for audience in [PredicateAudience.search, .commandLine] {
                    do {
                        let predicate = try StreamFilter.Predicate(source, for: audience)
                        XCTAssertTrue(try predicate.evaluate(on: values), "\(record.label): \(source)")
                    } catch {
                        XCTFail("\(record.label): \(source): \(error)")
                    }
                }
                kinds.insert("\(outline.values[index].kind)\(outline.values[index].isInArray ? " in array" : "")")
                checked += 1
            }
        }
        XCTAssertGreaterThan(checked, 5_000)
        XCTAssertLessThan(long, 10)
        XCTAssertTrue(kinds.isSuperset(of: ["string", "number", "boolean", "object", "array", "string in array",
                                            "number in array", "object in array"]), "\(kinds)")
    }

    /// A network flow's record has no `es_event_type` or `event_type`, so no value of one copies as a predicate on
    /// either, and its event's own key does.
    func testAFlowsValuesNeverNameItsType() throws {
        let encoder = ExportEncoder(model: try XCTUnwrap(ExportEncoder.model), pretty: true)
        for record in SyntheticCorpus.networkRecords() {
            let text = String(decoding: encoder.line(for: record.message), as: UTF8.self)
            encoder.reset()
            let outline = JSONOutline(text)
            let sources = outline.values.indices.compactMap {
                ValuePredicate.predicate(for: $0, in: outline, text: text as NSString)
            }
            XCTAssertFalse(sources.contains { $0.hasPrefix("es_event_type") || $0.hasPrefix("event_type") },
                           record.label)
            let name = try XCTUnwrap(record.message.event.macMonitorEvent?.name)
            XCTAssertTrue(sources.contains("event.\(name) != nil"), record.label)
        }
    }

    /// An event type's predicate is its `es_event_type` for an Endpoint Security event, and its event's key for a
    /// network flow, whose record has no `es_event_type`. Each matches its own type's records alone, and the Security
    /// Extension can run it.
    func testEventType() throws {
        XCTAssertEqual(ValuePredicate.eventType("ES_EVENT_TYPE_NOTIFY_EXEC"),
                       #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#)
        XCTAssertEqual(ValuePredicate.eventType("new_flow"), "event.new_flow != nil")
        XCTAssertEqual(ValuePredicate.eventType("flow_closed"), "event.flow_closed != nil")
        let names = MacMonitorEvent.allCases.map(\.name) + ["ES_EVENT_TYPE_NOTIFY_EXEC"]
        for name in names {
            XCTAssertNil(IndicatorCompiler.problem(with: ValuePredicate.eventType(name)), name)
        }
        for record in try SyntheticCorpus.records() {
            let values = try self.record(exportText(record.message))
            let type = try XCTUnwrap(record.message.es_event_type)
            for name in names {
                let matches = try StreamFilter.Predicate(ValuePredicate.eventType(name), for: .indicator)
                XCTAssertEqual(try matches.evaluate(on: values), name == type, "\(record.label): \(name)")
            }
        }
    }
}
