//
//  UndeterminedIndicatorsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Undetermined indicators on the wire
/// Pins `indicators_undetermined` as an event carries it from the Security Extension: each entry is a hit's keys and
/// `reason` in one object, through both encoders; a reason this build doesn't know is kept; and a list that can't be
/// read is `nil`, so its event still decodes, as the app and File > Open Trace read it.
final class UndeterminedIndicatorsTests: XCTestCase {
    /// An entry writes the hit's keys and `reason` in one object, the same through the Security Extension's streaming
    /// encoder and `JSONEncoder`, and the reasons this build knows are the schema's two.
    func testAnEntryEncodesFlat() throws {
        let entry = Self.undetermined.entries[1]
        let object = try jsonObject(encoding: entry)
        XCTAssertEqual(Set(object.keys), Set(try jsonObject(encoding: entry.hit).keys).union(["reason"]))
        XCTAssertEqual(object["reason"] as? String, "value_limit")
        XCTAssertEqual(object["name"] as? String, entry.hit.name)
        let streamed = try JSONSerialization.jsonObject(with: try StreamingJSONEncoder().encode(entry))
        XCTAssertEqual(streamed as? NSDictionary, object as NSDictionary)
        XCTAssertEqual(UndeterminedReason.known.map(\.rawValue), ["scan_budget", "value_limit"])
        XCTAssertEqual(UndeterminedReason(rawValue: "scan_budget"), .scanBudget)
    }

    /// An event's undetermined indicators come back from the wire as they went in, through both encoders, beside its
    /// verdicts; an event without them has no key.
    func testTheyRoundTripOnTheWire() throws {
        var message = try XCTUnwrap(SyntheticCorpus.records().first).message
        XCTAssertNil(try jsonObject(encoding: message)["indicators_undetermined"])
        message.indicators = IndicatorVerdictsTests.verdicts
        message.indicators_undetermined = Self.undetermined
        for data in [try StreamingJSONEncoder().encode(message), try JSONEncoder().encode(message)] {
            let decoded = try JSONDecoder().decode(Message.self, from: data)
            XCTAssertEqual(decoded.indicators_undetermined, Self.undetermined)
            XCTAssertEqual(decoded.indicators, IndicatorVerdictsTests.verdicts)
        }
        XCTAssertEqual(try TraceImporter.message(from: try JSONEncoder().encode(message)).indicators_undetermined,
                       Self.undetermined)
    }

    /// A reason this build doesn't know is kept by name, and written back as it came.
    func testAnUnknownReasonIsKept() throws {
        var entry = try jsonObject(encoding: Self.undetermined.entries[0])
        entry["reason"] = "hit_limit"
        for decoded in [decoded(with:), imported(with:)] {
            let entries = try XCTUnwrap(try decoded([entry])).entries
            XCTAssertEqual(entries.map(\.reason), [.other("hit_limit")])
            XCTAssertEqual(try jsonObject(encoding: entries[0])["reason"] as? String, "hit_limit")
        }
    }

    /// A list that can't be read is `nil`, and its event still decodes: not an array, an entry without its reason, a
    /// reason that's `null` or empty, an entry whose hit can't be read, and `null`; on the wire, a reason that isn't a
    /// string too. A missing key is `nil` too, and `[]` reads as an empty list. Open Trace, whose decoder fills in
    /// missing values, reads each the same way, so it never keeps an entry with a made-up reason.
    func testAnUnreadableListIsNil() throws {
        let entry = try jsonObject(encoding: Self.undetermined.entries[0])
        /// The entry without one of its keys.
        /// - Parameter key: The key to leave out.
        /// - Returns: The entry's other keys and values.
        func without(_ key: String) -> [String: Any] { entry.filter { $0.key != key } }
        /// The entry with one key's value replaced or added.
        /// - Parameters:
        ///   - key: The key to set.
        ///   - value: Its new value.
        /// - Returns: The entry with that value.
        func with(_ key: String, _ value: Any) -> [String: Any] { entry.merging([key: value]) { $1 } }
        let unreadable: [Any] = [
            "Dylib inserted", [1], [without("reason")], [with("reason", NSNull())], [with("reason", "")],
            [without("severity")], [without("id")], [entry, without("evaluated_by")], NSNull(),
        ]
        for decoded in [decoded(with:), imported(with:)] {
            for value in unreadable {
                XCTAssertNil(try decoded(value), "\(value)")
            }
            XCTAssertNil(try decoded(nil))
            XCTAssertEqual(try decoded([Any]()), UndeterminedIndicators([]))
            XCTAssertEqual(try decoded([entry]), UndeterminedIndicators([Self.undetermined.entries[0]]))
        }
        XCTAssertNil(try decoded(with: [with("reason", 3)]), "Open Trace reads a number as its text")
    }
}


// MARK: - Helpers
extension UndeterminedIndicatorsTests {
    /// Two indicators the Security Extension couldn't rule out, a reason each: one Mac Monitor ships, with its
    /// tactic, and one of someone's own.
    static let undetermined: UndeterminedIndicators = {
        let hits = IndicatorVerdictsTests.verdicts.hits
        return UndeterminedIndicators([IndicatorUndetermined(hits[0], reason: .scanBudget),
                                       IndicatorUndetermined(hits[1], reason: .valueLimit)])
    }()

    /// A synthetic event's wire JSON with its `indicators_undetermined` set to a value, decoded as the app decodes the
    /// wire.
    ///
    /// - Parameter value: The value, or `nil` to leave the key out.
    /// - Returns: The decoded event's undetermined indicators.
    /// - Throws: When the event doesn't decode: a list that can't be read must never do that.
    private func decoded(with value: Any?) throws -> UndeterminedIndicators? {
        try JSONDecoder().decode(Message.self, from: try wire(with: value)).indicators_undetermined
    }

    /// The same, read as File > Open Trace reads it.
    ///
    /// - Parameter value: The value, or `nil` to leave the key out.
    /// - Returns: The imported event's undetermined indicators.
    /// - Throws: When the event doesn't import: a list that can't be read must never do that.
    private func imported(with value: Any?) throws -> UndeterminedIndicators? {
        try TraceImporter.message(from: try wire(with: value)).indicators_undetermined
    }

    /// - Parameter value: The `indicators_undetermined` value, or `nil` to leave the key out.
    /// - Returns: A synthetic event's wire JSON with the key set to it.
    /// - Throws: When the event can't be encoded.
    private func wire(with value: Any?) throws -> Data {
        var object = try jsonObject(encoding: try XCTUnwrap(SyntheticCorpus.records().first).message)
        object["indicators_undetermined"] = value
        return try JSONSerialization.data(withJSONObject: object)
    }
}
