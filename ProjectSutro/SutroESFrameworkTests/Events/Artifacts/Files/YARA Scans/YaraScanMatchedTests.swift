//
//  YaraScanMatchedTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/27/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - A scan a rule matched
/// Pins ``YaraScan/matched``, which decides whether Event Facts shows a scan: only when one of XProtect's rules
/// matched, a report-only rule included. A scan that matched nothing, and one that didn't run, aren't shown.
final class YaraScanMatchedTests: XCTestCase {
    func testOnlyAScanARuleMatchedIsShown() {
        XCTAssertTrue(Self.matchedScan.matched)
        let reportOnly = YaraScan(status: YaraScan.scanned, xprotectVersion: "5377",
                                  matches: [YaraMatch(identifier: "XProtect_HUNT", name: nil, matchType: 4)])
        XCTAssertTrue(reportOnly.matched)
        XCTAssertFalse(YaraScan(status: YaraScan.scanned, xprotectVersion: "5377").matched)
        for status in [YaraScan.tooLarge, YaraScan.overBudget, YaraScan.busy, YaraScan.unreadable, YaraScan.changed,
                       YaraScan.unavailable, YaraScan.timedOut, YaraScan.tooManyMatches] {
            XCTAssertFalse(YaraScan.notScanned(status).matched, status)
        }
    }
}
