//
//  EventAgeTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Ages as they're shown
/// Pins ``EventAge``, which the app shows executable and process ages with: seconds to two places under a minute, then
/// whole minutes, hours and days, and nothing for an age that's unknown or negative.
final class EventAgeTests: XCTestCase {
    /// Each unit starts at its threshold, and each is rounded down once the age is rounded to the millisecond: no
    /// age under a minute reads "60.00s".
    func testThresholds() {
        let cases: [(TimeInterval, String)] = [
            (0, "0.00s"), (0.29, "0.29s"), (3.25, "3.25s"), (3.256, "3.25s"), (59.994, "59.99s"), (59.996, "59.99s"),
            (59.9996, "1min"), (60, "1min"), (3599, "59min"), (3600, "1h"), (86_399, "23h"), (86_400, "1 day"),
            (2 * 86_400 - 1, "1 day"), (2 * 86_400, "2 days"), (12 * 86_400 + 5, "12 days"),
        ]
        for (seconds, text) in cases {
            XCTAssertEqual(EventAge.text(seconds: seconds), text, "\(seconds) s")
        }
    }

    /// An unknown or negative age has no text.
    func testUnknownOrNegativeAgeHasNoText() {
        XCTAssertNil(EventAge.text(seconds: nil))
        XCTAssertNil(EventAge.text(seconds: -0.001))
        XCTAssertNil(EventAge.text(seconds: .infinity))
    }

    /// A stored age in milliseconds is read as seconds, and a negative one (the clock stepped back) as none.
    func testSecondsFromMilliseconds() {
        XCTAssertEqual(EventAge.seconds(fromMilliseconds: NSNumber(value: 3_250)), 3.25)
        XCTAssertEqual(EventAge.seconds(fromMilliseconds: NSNumber(value: 0)), 0)
        XCTAssertNil(EventAge.seconds(fromMilliseconds: NSNumber(value: -5)))
        XCTAssertNil(EventAge.seconds(fromMilliseconds: nil))
    }
}
