//
//  XCTestCase+Indicators.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Indicators for stamping tests
extension XCTestCase {
    /// The shipped indicators, compiled once, as the Security Extension compiles them.
    static let shippedIndicators = CompiledIndicators(Indicator.defaults)

    /// A shipped indicator's identity.
    ///
    /// - Parameter name: Its name, such as "Plist modified".
    /// - Returns: Its identity.
    /// - Throws: A failure when no shipped indicator has the name.
    func shippedID(_ name: String) throws -> UUID {
        try XCTUnwrap(Indicator.defaults.first { $0.name == name }?.id, "No shipped indicator named \(name)")
    }

    /// An indicator of someone's own.
    ///
    /// - Parameters:
    ///   - name: Its name.
    ///   - predicate: Its predicate.
    ///   - severity: Its severity.
    /// - Returns: The indicator.
    func ownIndicator(_ name: String, _ predicate: String, severity: IndicatorSeverity = .medium) -> Indicator {
        Indicator(name: name, description: "", symbol: "star", color: .blue, predicate: predicate, severity: severity)
    }

    /// The shipped indicators Mac Monitor's own matching (``IndicatorMatcher``) finds an event matches, as it stores
    /// the event: what the Security Extension's stamp must name.
    ///
    /// - Parameter message: The event.
    /// - Returns: Their identities, in the set's order.
    /// - Throws: The error storing the event.
    func matcherHits(_ message: Message) throws -> [UUID] {
        try withEventStore([message]) { _, stored in
            IndicatorMatcher(Indicator.defaults).matches(stored[0]).map(\.id)
        }
    }

    /// Check that verdicts are all the Security Extension's, each as its indicator says: name, severity, and whether
    /// it's shipped.
    ///
    /// - Parameters:
    ///   - verdicts: The verdicts.
    ///   - indicators: The indicators they come from.
    ///   - file: The caller's file.
    ///   - line: The caller's line.
    func assertStamped(_ verdicts: IndicatorVerdicts?, from indicators: [Indicator] = Indicator.defaults,
                       file: StaticString = #filePath, line: UInt = #line) {
        guard let verdicts else { return XCTFail("Not evaluated", file: file, line: line) }
        let shipped = Set(Indicator.defaults.map(\.id))
        for hit in verdicts.hits {
            guard let indicator = indicators.first(where: { $0.id == hit.id }) else {
                XCTFail("\(hit.name) isn't in the set", file: file, line: line)
                continue
            }
            XCTAssertEqual(hit.evaluated_by, .securityExtension, file: file, line: line)
            XCTAssertEqual(hit.name, indicator.name, file: file, line: line)
            XCTAssertEqual(hit.severity, indicator.severity, hit.name, file: file, line: line)
            XCTAssertEqual(hit.isDefault, shipped.contains(hit.id), hit.name, file: file, line: line)
        }
    }
}
