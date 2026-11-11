//
//  RecordFieldParityTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Record fields, parity with the record
/// Pins record fields (``RecordPathTrie``) to the record: every key path of the telemetry schema a rule can compare
/// has, on every event Mac Monitor's tests have, the value a predicate on the event's record compares, read from the
/// event's own encoding as the Security Extension reads it. A key path that differs is named, with an event it differs
/// on, so a change to an event that breaks one fails here rather than in a rule.
final class RecordFieldParityTests: XCTestCase {
    /// Every key path a rule can compare, on every event of the synthetic corpus, the fixtures and the lineage trace,
    /// has the record's value.
    func testEverySchemaPathIsTheRecords() throws {
        let paths = RecordSchema.paths.keys.compactMap { path -> (String, IndicatorField.Kind)? in
            if case .kind(let kind) = RecordSchema.lookup(path) { (path, kind) } else { nil }
        }
        XCTAssertGreaterThan(paths.count, 500)
        let fields = paths.map { path, kind in IndicatorField(path: path) ?? RecordFields.shared.field(path, kind: kind) }
        let trie = RecordPathTrie(fields.filter { !$0.isDirect })
        let messages = try SyntheticCorpus.records().map(\.message) + allFixtureMessages() + lineageTrace()
        let records = try MessageValuesParityTests().records(of: messages)
        var differing: [String: String] = [:], valued = Set<String>()
        for (message, record) in zip(messages, records) {
            var read: [IndicatorField: IndicatorValue] = [:]
            trie.read(message) { field, value in read[field] = value }
            for field in trie.fields {
                let mine = read[field] ?? .null
                let theirs = IndicatorValue(object: record.value(forKeyPath: field.path))
                if !mine.isNull { valued.insert(field.path) }
                guard mine != theirs, differing[field.path] == nil else { continue }
                differing[field.path] = "\(message.es_event_type ?? "?"): read \(mine), record \(theirs.map(\.description) ?? "?")"
            }
        }
        let report = differing.sorted { $0.key < $1.key }.map { "\($0.key)  \($0.value)" }.joined(separator: "\n")
        XCTAssertTrue(differing.isEmpty, "\(differing.count) key paths differ from the record:\n\(report)")
        print("[record fields] \(trie.fields.count) key paths, \(valued.count) with a value on some event")
    }
}
