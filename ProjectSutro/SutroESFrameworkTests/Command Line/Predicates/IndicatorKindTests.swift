//
//  IndicatorKindTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Kinds of rule
/// Pins the guard on an indicator's `kind`: this build reads rules on one event, with or without the key, and never
/// reads a later build's rule over several events as one. Saved, such a rule is kept as it was and written back; in a
/// shared file, it isn't imported.
final class IndicatorKindTests: XCTestCase {
    /// An indicator without a kind is a rule on one event, and so is one whose kind says so.
    func testEventKindDecodes() throws {
        XCTAssertEqual(Indicator.kind, "event")
        for kind in ["", #", "kind": "event""#] {
            let json = #"{"name": "Mine", "predicate": "TRUEPREDICATE"\#(kind)}"#
            XCTAssertEqual(try JSONDecoder().decode(Indicator.self, from: Data(json.utf8)).name, "Mine", kind)
        }
    }

    /// Any other kind doesn't decode, and says why, and nor does a kind that isn't a string.
    func testOtherKindsDontDecode() {
        for kind in [#""sequence""#, #""EVENT""#, "3"] {
            let json = #"{"name": "Mine", "predicate": "TRUEPREDICATE", "kind": \#(kind)}"#
            XCTAssertThrowsError(try JSONDecoder().decode(Indicator.self, from: Data(json.utf8)), kind)
        }
        let file = Data(#"""
        {"format": "com.swiftlydetecting.indicators", "version": 1, "indicators": [
          {"name": "Mine", "predicate": "TRUEPREDICATE", "kind": "sequence"}
        ]}
        """#.utf8)
        XCTAssertThrowsError(try IndicatorExchange.indicators(from: file)) { error in
            let message = (error as? IndicatorExchange.ImportError)?.message ?? ""
            XCTAssertTrue(message.contains("kind sequence"), message)
        }
    }

    /// A saved sequence rule, in full or as a reference to one a later build ships, is kept as it was saved and
    /// written back after the rest, and none of it runs as a rule on one event.
    func testSavedSequencesAreKept() throws {
        let sequence: [String: Any] = ["id": UUID().uuidString, "name": "Download then run", "kind": "sequence",
                                       "predicate": "TRUEPREDICATE", "steps": [["predicate": "TRUEPREDICATE"]]]
        let reference: [String: Any] = ["default": UUID().uuidString, "kind": "sequence", "isEnabled": false]
        let shipped: [String: Any] = ["default": Indicator.defaults[0].id.uuidString, "isEnabled": false]
        /// A kind that isn't a string isn't an event's either, as a full entry's isn't.
        let (second, third) = (Indicator.defaults[1], Indicator.defaults[2])
        let unreadable: [String: Any] = ["default": second.id.uuidString, "kind": 3, "isEnabled": !second.isEnabled]
        let event: [String: Any] = ["default": third.id.uuidString, "kind": NSNull(), "isEnabled": !third.isEnabled]
        let data = try JSONSerialization.data(withJSONObject: [
            "entries": [sequence, shipped, reference, unreadable, event], "deleted": [],
        ])
        let saved = try XCTUnwrap(SavedIndicators(data: data))
        XCTAssertEqual(saved.undecodableCount, 3)
        XCTAssertEqual(saved.indicators.map(\.id), [0, 2, 1].map { Indicator.defaults[$0].id }
                        + Indicator.defaults.dropFirst(3).map(\.id))
        XCTAssertFalse(saved.indicators[0].isEnabled)
        XCTAssertEqual(saved.indicators[1].isEnabled, !third.isEnabled)
        XCTAssertEqual(saved.indicators[2].isEnabled, second.isEnabled)
        let written = try jsonObject(try XCTUnwrap(saved.encoded()))
        let entries = try XCTUnwrap(written["entries"] as? [[String: Any]])
        XCTAssertEqual(entries.suffix(3).map { $0["kind"] as? String }, ["sequence", "sequence", nil])
        XCTAssertEqual(entries.suffix(3).last?["kind"] as? Int, 3)
        XCTAssertEqual(entries.dropLast().last?["default"] as? String, reference["default"] as? String)
        XCTAssertEqual(entries.suffix(3).first?["steps"] as? [[String: String]], [["predicate": "TRUEPREDICATE"]])
    }
}
