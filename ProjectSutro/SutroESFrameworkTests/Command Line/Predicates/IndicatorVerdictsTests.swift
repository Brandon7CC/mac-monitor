//
//  IndicatorVerdictsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Verdicts on the wire
/// Pins the verdicts an event carries from the Security Extension: a hit's keys, a round trip through both encoders,
/// a producer this build doesn't know, and a list that can't be read, which leaves its event "not evaluated" rather
/// than dropping it.
final class IndicatorVerdictsTests: XCTestCase {
    /// A hit writes every key, `null` for none, and its severity and evaluator by name.
    func testHitWritesEveryKey() throws {
        let indicator = Indicator(name: "Mine", description: "", symbol: "star", color: .red,
                                  predicate: "TRUEPREDICATE", severity: .low)
        let hit = try jsonObject(encoding: IndicatorHit(indicator, isDefault: false, evaluatedBy: .securityExtension))
        XCTAssertEqual(Set(hit.keys), ["id", "name", "tactic", "tactic_id", "technique", "severity", "default",
                                       "edited", "evaluated_by"])
        XCTAssertEqual(hit["edited"] as? Bool, false)
        XCTAssertTrue(hit["tactic"] is NSNull && hit["tactic_id"] is NSNull && hit["technique"] is NSNull)
        XCTAssertEqual(hit["severity"] as? String, "low")
        XCTAssertEqual(hit["evaluated_by"] as? String, "security_extension")
        XCTAssertEqual(IndicatorEvaluator.known.map(\.rawValue), ["security_extension", "export"])
    }

    /// An event's verdicts come back from the wire as they went in, from the Security Extension's streaming encoder
    /// and from `JSONEncoder`, hits and none; an event without them has no key.
    func testVerdictsRoundTripOnTheWire() throws {
        var message = try XCTUnwrap(SyntheticCorpus.records().first).message
        XCTAssertNil(message.indicators)
        XCTAssertNil(try jsonObject(encoding: message)["indicators"])
        for verdicts in [Self.verdicts, IndicatorVerdicts()] {
            message.indicators = verdicts
            for data in [try StreamingJSONEncoder().encode(message), try JSONEncoder().encode(message)] {
                XCTAssertEqual(try JSONDecoder().decode(Message.self, from: data).indicators, verdicts)
            }
        }
    }

    /// A producer this build doesn't know is kept by name, and written back as it came.
    func testUnknownEvaluatorIsKept() throws {
        var hit = try jsonObject(encoding: Self.verdicts.hits[0])
        hit["evaluated_by"] = "siem_shipper"
        let decoded = try decodedIndicators(with: [hit])
        XCTAssertEqual(decoded?.hits.first?.evaluated_by, .other("siem_shipper"))
        XCTAssertEqual(try decoded.map { try jsonObject(encoding: $0.hits[0])["evaluated_by"] as? String },
                       "siem_shipper")
    }

    /// A list that can't be read is "not evaluated", and its event still decodes: not an array, an element that isn't
    /// a hit, a hit without its severity or evaluator (as Mac Monitor 3.0 listed them) or its `edited` (as earlier
    /// 3.1 builds stored them), with a severity this build doesn't know, or with no evaluator's name. `null` and a
    /// missing key are `nil` too, and `[]` is evaluated with nothing matched. File > Open Trace, whose decoder fills in
    /// missing values, reads each the same way, so it never keeps a hit with made-up values.
    func testUnreadableListIsNotEvaluated() throws {
        let hit = try jsonObject(encoding: Self.verdicts.hits[0])
        func without(_ key: String) -> [String: Any] { hit.filter { $0.key != key } }
        func with(_ key: String, _ value: Any) -> [String: Any] { hit.merging([key: value]) { $1 } }
        let unreadable: [Any] = [
            "Reflective loading", ["name": "Reflective loading"], [1], [without("severity")],
            [without("evaluated_by")], [with("severity", "critical")], [with("evaluated_by", "")],
            [with("id", "not a UUID")], [without("id")], [with("id", NSNull())], [hit, without("name")],
            [with("name", NSNull())], [without("default")], [with("default", NSNull())], [without("edited")],
            [with("edited", NSNull())], [with("edited", "yes")], NSNull(),
        ]
        for decoded in [decodedIndicators(with:), importedIndicators(with:)] {
            for value in unreadable {
                XCTAssertNil(try decoded(value), "\(value)")
            }
            XCTAssertNil(try decoded(nil))
            XCTAssertEqual(try decoded([Any]()), IndicatorVerdicts())
            XCTAssertEqual(try decoded([hit]), IndicatorVerdicts([Self.verdicts.hits[0]]))
        }
    }
}


// MARK: - Helpers
extension IndicatorVerdictsTests {
    /// Two hits the Security Extension found: one Mac Monitor ships, with its tactic, and one of someone's own.
    static let verdicts: IndicatorVerdicts = {
        let own = Indicator(name: "Mine", description: "", symbol: "star", color: .red, predicate: "TRUEPREDICATE",
                            severity: .high)
        return IndicatorVerdicts([IndicatorHit(Indicator.defaults[1], isDefault: true, evaluatedBy: .securityExtension),
                                  IndicatorHit(own, isDefault: false, evaluatedBy: .securityExtension)])
    }()

    /// A synthetic event's wire JSON with its `indicators` set to a value, decoded as the app decodes the wire.
    ///
    /// - Parameter value: The `indicators` value, or `nil` to leave the key out.
    /// - Returns: The decoded event's verdicts.
    /// - Throws: When the event doesn't decode: a list that can't be read must never do that.
    private func decodedIndicators(with value: Any?) throws -> IndicatorVerdicts? {
        try JSONDecoder().decode(Message.self, from: try wire(with: value)).indicators
    }

    /// The same, read as File > Open Trace reads it.
    ///
    /// - Parameter value: The `indicators` value, or `nil` to leave the key out.
    /// - Returns: The imported event's verdicts.
    /// - Throws: When the event doesn't import: a list that can't be read must never do that.
    private func importedIndicators(with value: Any?) throws -> IndicatorVerdicts? {
        try TraceImporter.message(from: try wire(with: value)).indicators
    }

    /// - Parameter value: The `indicators` value, or `nil` to leave the key out.
    /// - Returns: A synthetic event's wire JSON with its `indicators` set to it.
    /// - Throws: When the event can't be encoded.
    private func wire(with value: Any?) throws -> Data {
        var object = try jsonObject(encoding: try XCTUnwrap(SyntheticCorpus.records().first).message)
        object["indicators"] = value
        return try JSONSerialization.data(withJSONObject: object)
    }
}
