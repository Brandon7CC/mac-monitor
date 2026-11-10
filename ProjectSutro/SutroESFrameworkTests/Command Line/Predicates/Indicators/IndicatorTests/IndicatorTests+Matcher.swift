//
//  IndicatorTests+Matcher.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Matcher
/// ``IndicatorMatcher`` against evaluating every indicator on every event's record, on events that each default and
/// built-in mark both matches and doesn't.
extension IndicatorTests {
    /// Routing by type and narrowing by the store never leave an indicator out, nor put one in: the matcher agrees with
    /// evaluating every default and built-in mark on every event of ``indicatorCorpus()``. Each one both matches some
    /// event and doesn't match another, and matches only events of the types its predicate names
    /// (``PredicateEventTypes``).
    func testMatcherAgreesWithEveryPredicate() throws {
        let indicators = Indicator.defaults + Indicator.builtInMarks
        let matcher = IndicatorMatcher(indicators)
        let predicates = try indicators.map { try StreamFilter.Predicate($0.predicate, for: .indicator) }
        let types = try zip(indicators, predicates).map { indicator, predicate in
            try XCTUnwrap(PredicateEventTypes.eventTypes(of: predicate.parsed), "\(indicator.name) names no types")
        }
        var hits = [Int](repeating: 0, count: indicators.count), misses = hits
        try withEventStore(try indicatorCorpus()) { _, stored in
            for event in stored {
                let record = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(event))
                                           as? NSDictionary)
                let type = event.es_event_type ?? ""
                var expected: [UUID] = []
                for (index, predicate) in predicates.enumerated() {
                    guard try predicate.evaluate(on: record) else {
                        misses[index] += 1
                        continue
                    }
                    hits[index] += 1
                    expected.append(indicators[index].id)
                    XCTAssertTrue(types[index].contains(type), "\(indicators[index].name) matched \(type)")
                }
                XCTAssertEqual(matcher.matches(event).map(\.id), expected, type)
            }
        }
        for (index, indicator) in indicators.enumerated() {
            XCTAssertGreaterThan(hits[index], 0, "\(indicator.name) matched no event")
            XCTAssertGreaterThan(misses[index], 0, "\(indicator.name) matched every event")
        }
    }

    /// Indicators whose predicates differ only in how a constant is normalized (``CanonicalSpellings``) are evaluated
    /// each on its own, not once for both: for `==` and `IN` only the one spelled as the event is matches, and for
    /// `!=` only the other, in either order.
    func testCanonicallyEqualPredicatesKeepTheirOwnVerdicts() throws {
        var message = try XCTUnwrap(SyntheticCorpus.records().map(\.message)
            .first { $0.es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" })
        message.target_path = CanonicalSpellings.nfd
        try withEventStore([message]) { _, stored in
            let event = try XCTUnwrap(stored.first)
            for pair in CanonicalSpellings.pairs {
                for indicators in [[pair.composed, pair.decomposed], [pair.decomposed, pair.composed]] {
                    XCTAssertEqual(IndicatorMatcher(indicators).matches(event).map(\.id), [pair.hit], pair.format)
                }
            }
        }
    }

    /// The synthetic corpus and the fixtures' lineage, then each record of ``defaultCases()`` and ``markCases()``
    /// laid over the corpus's first event of its type, the record's values in place of the event's, so each indicator
    /// hits some event and misses another.
    ///
    /// - Returns: The events.
    /// - Throws: The error making the corpus, or a failure when the corpus has no event of a record's type or a
    ///   record's values don't decode as the event's.
    func indicatorCorpus() throws -> [Message] {
        let corpus = try SyntheticCorpus.records().map(\.message)
        var bases: [String: Message] = [:]
        for message in corpus { bases[message.es_event_type ?? ""] = bases[message.es_event_type ?? ""] ?? message }
        let laid = try (defaultCases() + markCases()).flatMap { [($0.0, $0.1), ($0.0, $0.2)] }.map { name, record in
            let type = try XCTUnwrap(record["es_event_type"] as? String, name)
            let base = try XCTUnwrap(bases[type], "\(name): the corpus has no \(type)")
            let event = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(base)) as? NSDictionary)
            let merged = Self.laying(Self.modeled(record), over: event)
            do {
                return try JSONDecoder().decode(Message.self, from: JSONSerialization.data(withJSONObject: merged))
            } catch {
                XCTFail("\(name): \(record) doesn't decode over a \(type): \(error)")
                throw error
            }
        }
        return corpus + (try lineageTrace()) + laid
    }

    /// A case's record as ``Message`` encodes it, which differs from the record a predicate reads in one way: an
    /// event's fields are its enum case's payload, under `_0`.
    ///
    /// - Parameter record: A case's record.
    /// - Returns: It with each of `event`'s values under `_0`.
    private static func modeled(_ record: NSDictionary) -> NSDictionary {
        guard let event = record["event"] as? NSDictionary else { return record }
        let modeled = NSMutableDictionary(dictionary: record), payloads = NSMutableDictionary()
        for case let (key as String, value) in event { payloads[key] = ["_0": value] }
        modeled["event"] = payloads
        return modeled
    }

    /// - Parameters:
    ///   - record: A case's record, as ``Message`` encodes it.
    ///   - event: An event, as ``Message`` encodes it.
    /// - Returns: The event's record with each of the case's values in place, objects merged key by key.
    private static func laying(_ record: NSDictionary, over event: NSDictionary) -> NSDictionary {
        let merged = NSMutableDictionary(dictionary: event)
        for case let (key as String, value) in record {
            if let inner = value as? NSDictionary, let outer = event[key] as? NSDictionary {
                merged[key] = laying(inner, over: outer)
            } else {
                merged[key] = value
            }
        }
        return merged
    }
}
