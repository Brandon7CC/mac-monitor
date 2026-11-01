//
//  QuitReasonTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/1/26.
//

import XCTest
import CoreServices
@testable import SutroESFramework


// MARK: - Quit reason
/// Pins which quits are macOS's own, so a warning before quitting never holds a logout, restart or shutdown (#86).
final class QuitReasonTests: XCTestCase {
    /// Logging out, restarting and shutting down, asked or confirmed, are macOS's quits.
    func testLogoutRestartAndShutdownAreTheSystems() {
        for code in [kAELogOut, kAEReallyLogOut, kAEShowRestartDialog, kAERestart, kAEShowShutdownDialog, kAEShutDown] {
            XCTAssertEqual(QuitReason(appleEventReason: code), .system, "\(code)")
        }
    }

    /// A quit with no reason, or any other, is a person's: Mac Monitor still warns.
    func testEverythingElseIsTheUsers() {
        XCTAssertEqual(QuitReason(appleEventReason: nil), .user)
        XCTAssertEqual(QuitReason(appleEventReason: 0), .user)
        XCTAssertEqual(QuitReason(appleEventReason: kAEQuitApplication), .user)
    }

    /// With no Apple Event being handled, as in a test or `NSApp.terminate(_:)`, the quit is a person's.
    func testNoAppleEventIsTheUsers() {
        XCTAssertEqual(QuitReason.current, .user)
    }
}
