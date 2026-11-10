//
//  IndicatorFieldTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Fields
/// Pins the fields the Security Extension reads: their places, their key paths, and that they cover every key path
/// Mac Monitor's shipped indicators read.
final class IndicatorFieldTests: XCTestCase {
    /// Each field's raw value is its place in `allCases`, from 0, which a lane's cache indexes by.
    func testRawValuesArePlaces() {
        for (place, field) in IndicatorField.allCases.enumerated() {
            XCTAssertEqual(Int(field.rawValue), place, field.path)
        }
        XCTAssertEqual(IndicatorField.closeFileType.description, "closeFileType")
        XCTAssertEqual(IndicatorField.iokitOpenUserClientClass.description, "iokitOpenUserClientClass")
        XCTAssertEqual(Set(IndicatorField.allCases.map(\.description)).count, IndicatorField.allCases.count)
        XCTAssertEqual(try IndicatorField.record("process.pid").description, "process.pid")
    }

    /// Each field has its own key path, and a key path names its field. One it doesn't serve names none.
    func testKeyPathsNameTheirFields() {
        XCTAssertEqual(Set(IndicatorField.allCases.map(\.path)).count, IndicatorField.allCases.count)
        for field in IndicatorField.allCases {
            XCTAssertEqual(IndicatorField(path: field.path), field)
        }
        for path in ["event.exec.launched_by_parent.path", "process", "event.exec", "", "target_path "] {
            XCTAssertNil(IndicatorField(path: path), path)
        }
    }

    /// The fields are the 30 key paths the shipped indicators compare, besides the payloads they test for their
    /// types, the event's type, which those tests are, and the rest of the signing identity: the exec target's team
    /// ID and platform binary, and the process's team ID.
    func testFieldsAreTheDefaultsPaths() throws {
        var read: Set<String> = []
        for indicator in Indicator.defaults {
            let predicate = try StreamFilter.Predicate(indicator.predicate, for: .indicator)
            _ = predicate.parsed.contains { expression in
                if expression.expressionType == .keyPath, PredicateEventTypes.payloads[expression.keyPath] == nil {
                    read.insert(expression.keyPath)
                }
                return false
            }
        }
        XCTAssertEqual(read.subtracting(["es_event_type"]).count, 30)
        let identity: Set = ["es_event_type", "event.exec.target.team_id", "event.exec.target.is_platform_binary",
                             "process.team_id"]
        XCTAssertEqual(Set(IndicatorField.allCases.map(\.path)), read.union(identity))
        XCTAssertEqual(IndicatorField.allCases.count, 34)
    }
}


// MARK: - Values
/// Pins ``IndicatorValue``: what it makes of Foundation's values, and that equal means the same bytes.
final class IndicatorValueTests: XCTestCase {
    /// `nil` and `NSNull` are null, a Boolean is 1 or 0, an integer is whole and a double isn't, and an array of
    /// strings is strings. Anything else is no value.
    func testFoundationValues() {
        XCTAssertEqual(IndicatorValue(object: nil), .null)
        XCTAssertEqual(IndicatorValue(object: NSNull()), .null)
        XCTAssertEqual(IndicatorValue(object: "a"), .string("a"))
        XCTAssertEqual(IndicatorValue(object: NSString(string: "a")), .string("a"))
        XCTAssertEqual(IndicatorValue(object: true), .number(1, isInteger: true))
        XCTAssertEqual(IndicatorValue(object: NSNumber(value: false)), .number(0, isInteger: true))
        XCTAssertEqual(IndicatorValue(object: NSNumber(value: 42)), .number(42, isInteger: true))
        XCTAssertEqual(IndicatorValue(object: NSNumber(value: 0.5)), .number(0.5, isInteger: false))
        XCTAssertEqual(IndicatorValue(object: ["a", "b"] as NSArray), .strings(["a", "b"]))
        XCTAssertEqual(IndicatorValue(object: [] as NSArray), .strings([]))
        XCTAssertNil(IndicatorValue(object: ["a", 1] as NSArray))
        XCTAssertNil(IndicatorValue(object: ["a": "b"] as NSDictionary))
        XCTAssertNil(IndicatorValue(object: Date()))
    }

    /// The JSON a record is read from gives the same values.
    func testRecordValues() throws {
        let record = try XCTUnwrap(JSONSerialization.jsonObject(
            with: Data(#"{"s": "x", "b": true, "i": 7, "n": null, "a": ["y"]}"#.utf8)) as? NSDictionary)
        XCTAssertEqual(IndicatorValue(object: record["s"]), .string("x"))
        XCTAssertEqual(IndicatorValue(object: record["b"]), IndicatorValue(true))
        XCTAssertEqual(IndicatorValue(object: record["i"]), IndicatorValue(7))
        XCTAssertEqual(IndicatorValue(object: record["n"]), .null)
        XCTAssertEqual(IndicatorValue(object: record["missing"]), .null)
        XCTAssertEqual(IndicatorValue(object: record["a"]), .strings(["y"]))
    }

    /// The initializers: `nil` is null, and a Boolean is the number a predicate compares.
    func testInitializers() {
        XCTAssertEqual(IndicatorValue(nil as String?), .null)
        XCTAssertEqual(IndicatorValue(nil as Int?), .null)
        XCTAssertEqual(IndicatorValue(-3), .number(-3, isInteger: true))
        XCTAssertEqual(IndicatorValue(false), .number(0, isInteger: true))
        XCTAssertTrue(IndicatorValue(nil as String?).isNull)
        XCTAssertFalse(IndicatorValue("").isNull)
    }

    /// Equal is the same bytes: an NFD string isn't its NFC spelling, though Swift's strings compare them equal, and
    /// a whole number isn't the same double.
    func testEqualIsTheSameBytes() {
        let nfc = "R\u{E9}sum\u{E9}", nfd = "Re\u{301}sume\u{301}"
        XCTAssertEqual(nfc, nfd)
        XCTAssertNotEqual(IndicatorValue(nfc), IndicatorValue(nfd))
        XCTAssertNotEqual(IndicatorValue.strings([nfc]), .strings([nfd]))
        XCTAssertEqual(IndicatorValue.strings([nfc]), .strings([nfc]))
        XCTAssertNotEqual(IndicatorValue.strings(["a"]), .strings(["a", "b"]))
        XCTAssertNotEqual(IndicatorValue.number(1, isInteger: true), .number(1, isInteger: false))
        XCTAssertNotEqual(IndicatorValue(""), .null)
        XCTAssertNotEqual(IndicatorValue("1"), IndicatorValue(1))
        XCTAssertEqual(IndicatorValue.string("/a/b".dropFirst(3)), IndicatorValue("b"))
    }

    /// Each value is written as a predicate writes it.
    func testDescriptions() {
        XCTAssertEqual(IndicatorValue.null.description, "nil")
        XCTAssertEqual(IndicatorValue("a \"b\"").description, #""a \"b\"""#)
        XCTAssertEqual(IndicatorValue(7).description, "7")
        XCTAssertEqual(IndicatorValue(true).description, "1")
        XCTAssertEqual(IndicatorValue.number(0.5, isInteger: false).description, "0.5")
        XCTAssertEqual(IndicatorValue.strings(["a", "b"]).description, #"{"a", "b"}"#)
        XCTAssertEqual(IndicatorValue("a\u{7F}\u{1}\n").description, #""a\u007F\u0001\n""#)
    }

    /// A string's description is a predicate's constant that `NSPredicate(format:)` reads back as the same string:
    /// with control characters, escapes, quotes, combining marks and scalars beyond the Basic Multilingual Plane.
    func testStringDescriptionsReadBackThroughAPredicate() {
        let strings = ["a\u{7F}b", "a\u{1}b", "\u{85}\u{9F}", "tab\there", "line\nbreak\r", #"q"uo\te"#, #"\n"#,
                       "Re\u{301}sume\u{301}", "\u{1F600}", "\u{2028}", "it's", ""]
        for string in strings {
            let value = IndicatorValue(string)
            let predicate = NSPredicate(format: "SELF == \(value.description)")
            XCTAssertTrue(predicate.evaluate(with: string), "\(string.debugDescription) as \(value)")
            XCTAssertFalse(predicate.evaluate(with: string + "x"), value.description)
        }
        let list = IndicatorValue.strings(strings)
        XCTAssertTrue(NSPredicate(format: "ANY SELF IN \(list.description)").evaluate(with: ["a\u{7F}b"]))
        XCTAssertEqual(NSPredicate(format: "SELF IN \(list.description)").predicateFormat,
                       NSPredicate(format: "SELF IN %@", strings).predicateFormat)
    }
}
