//
//  PredicateHardeningTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/10/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Predicates someone typed
/// Pins what a predicate anyone can type can't do to the process that reads it, the Security Extension included.
/// `NSExpression` raises, and Swift can't catch it, when a property is read from an expression of another kind, and
/// a compile must take no longer for how a predicate nests.
final class PredicateHardeningTests: XCTestCase {
    /// A set that holds a key path among its constants names no event types, and is refused rather than read as
    /// constants: reading a key path's `constantValue` raises.
    func testASetWithAKeyPathIsRefused() {
        let source = #"es_event_type IN {"ES_EVENT_TYPE_NOTIFY_EXEC", target_path}"#
        XCTAssertEqual(PredicateEventTypes.namedEventTypes(in: NSPredicate(format: source)), [])
        guard case .failure = IndicatorCompiler.compile(source) else { return XCTFail("It compiled") }
    }

    /// `valueForKeyPath:` given a constant rather than a key path is refused for every audience: reading a
    /// constant's `keyPath` raises. A variable's key path still reads.
    func testValueForKeyPathOfAConstantIsRefused() {
        let inside = #"SUBQUERY(process_group, $e, FUNCTION($e, 'valueForKeyPath:', 'process.pid') == 1).@count > 0"#
        let outside = #"FUNCTION(SUBQUERY(process_group, $e, TRUEPREDICATE), 'valueForKeyPath:', 'x') == 1"#
        for audience in [PredicateAudience.search, .commandLine, .indicator] {
            XCTAssertThrowsError(try StreamFilter.Predicate(inside, for: audience), "\(audience.name)")
            XCTAssertThrowsError(try StreamFilter.Predicate(outside, for: audience), "\(audience.name)")
        }
        let variable = #"SUBQUERY(process_group, $e, $e.process.pid == 1).@count > 0"#
        XCTAssertNoThrow(try StreamFilter.Predicate(variable, for: .search))
        XCTAssertEqual(NSExpression(format: "$e.process.pid").keyPath(of: "e"), "process.pid")
        XCTAssertNil(NSExpression(format: "FUNCTION($e, 'valueForKeyPath:', 'process.pid')").keyPath(of: "e"))
    }

    /// `AND`s and `OR`s nested in turn, as deep as a rule may nest, compile at once: flattening each level twice
    /// took twice as long for every level, minutes for this one.
    func testAlternatingNestingCompilesAtOnce() {
        var source = #"context == "a""#
        for level in 0..<30 { source = "context == \"a\" \(level % 2 == 0 ? "OR" : "AND") (\(source))" }
        let start = Date()
        guard case .success = IndicatorCompiler.compile("event.exec != nil AND (\(source))") else {
            return XCTFail("It didn't compile")
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 1)
    }
}
