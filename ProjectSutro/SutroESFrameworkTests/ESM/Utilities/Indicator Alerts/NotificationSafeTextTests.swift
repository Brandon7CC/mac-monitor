//
//  NotificationSafeTextTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Notification-safe text
/// Pins how event text is cleaned and capped for a notification: what's removed or turned into a space, what's
/// kept, and how lengths count.
final class NotificationSafeTextTests: XCTestCase {
    /// Newlines, tabs and other C0 controls, DEL, C1 controls and the line and paragraph separators become one
    /// space; runs collapse, and the ends are trimmed.
    func testControlsBecomeOneSpace() {
        XCTAssertEqual(NotificationSafeText.clean("a\nb\tc\u{1B}[31md\u{7F}e\u{85}f\r\n g"), "a b c [31md e f g")
        XCTAssertEqual(NotificationSafeText.clean(" \n lead  and   trail \t"), "lead and trail")
        XCTAssertEqual(NotificationSafeText.clean("a\u{2028}High: Fake\u{2029}b"), "a High: Fake b")
    }

    /// Bidirectional and zero-width characters are removed, so a name can't show backwards or hide a part.
    func testBidiAndZeroWidthAreRemoved() {
        XCTAssertEqual(NotificationSafeText.clean("evil\u{202E}fdp.app"), "evilfdp.app")
        XCTAssertEqual(NotificationSafeText.clean("\u{2066}a\u{2069}\u{061C}b\u{200E}"), "ab")
        XCTAssertEqual(NotificationSafeText.clean("Lit\u{200B}tle\u{200C}Sn\u{200D}it\u{2060}ch\u{FEFF}"),
                       "LittleSnitch")
    }

    /// Ordinary non-ASCII text is kept.
    func testNonASCIITextIsKept() {
        XCTAssertEqual(NotificationSafeText.clean("Résumé 日本語 ü"), "Résumé 日本語 ü")
    }

    /// Caps count scalars, the ellipsis included, so combining marks can't stretch a line; text within its cap is
    /// kept whole.
    func testCapsCountScalars() {
        XCTAssertEqual(NotificationSafeText.truncated("abcdef", to: 6), "abcdef")
        XCTAssertEqual(NotificationSafeText.truncated("abcdefg", to: 6), "abcde\u{2026}")
        let stacked = "e" + String(repeating: "\u{0301}", count: 100)
        XCTAssertEqual(NotificationSafeText.truncated(stacked, to: 64).unicodeScalars.count, 64)
    }

    /// A path is cut in its middle, so its start and its file name show.
    func testPathsAreCutInTheMiddle() {
        let path = "/Users/a/Library/LaunchAgents/com.example.agent.plist"
        XCTAssertEqual(NotificationSafeText.middleTruncated(path, to: path.count), path)
        let cut = NotificationSafeText.middleTruncated(path, to: 21)
        XCTAssertEqual(cut, "/Users/a/L\u{2026}gent.plist")
        XCTAssertEqual(cut.unicodeScalars.count, 21)
    }

    /// The home folder shows as `~`, only as a whole folder.
    func testHomeShowsAsTilde() {
        let home = "/Users/brandon"
        XCTAssertEqual(NotificationSafeText.abbreviatingHome("/Users/brandon/Library/x", home: home), "~/Library/x")
        XCTAssertEqual(NotificationSafeText.abbreviatingHome("/Users/brandon", home: home), "~")
        XCTAssertEqual(NotificationSafeText.abbreviatingHome("/Users/brandonx/a", home: home), "/Users/brandonx/a")
        XCTAssertEqual(NotificationSafeText.abbreviatingHome("/etc/hosts", home: "/"), "/etc/hosts")
    }
}
