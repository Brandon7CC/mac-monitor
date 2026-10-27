//
//  UpdateEngineTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/27/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Install replies and progress
final class UpdateEngineTests: XCTestCase {
    /// A failed request is `.unavailable`, a `nil` reply is installed, and a raw value is its failure. One this build
    /// doesn't know is the installer's.
    func testInstallRepliesDecode() {
        XCTAssertEqual(UpdateFailure.decode(nil), .unavailable)
        XCTAssertNil(UpdateFailure.decode(.some(nil)))
        for failure in UpdateFailure.allCases {
            XCTAssertEqual(UpdateFailure.decode(.some(failure.rawValue)), failure)
            XCTAssertFalse(failure.message.isEmpty, failure.rawValue)
        }
        XCTAssertEqual(UpdateFailure.decode(.some("somethingNewer")), .installer)
    }

    /// The steps go in order, the whole install only moves forward, and the download's fraction is clamped.
    func testProgressMovesForward() throws {
        let steps: [UpdateProgress] = [.downloading(fraction: 0), .downloading(fraction: 0.5),
                                       .downloading(fraction: 1), .verifying, .installing, .reopening]
        XCTAssertEqual(steps.map(\.step), [0, 0, 0, 1, 2, 3])
        XCTAssertEqual(steps.map(\.fraction), steps.map(\.fraction).sorted())
        XCTAssertEqual(UpdateProgress.downloading(fraction: 2).fraction,
                       UpdateProgress.downloading(fraction: 1).fraction)
        XCTAssertEqual(UpdateProgress.downloading(fraction: -1).fraction, 0)
        XCTAssertEqual(UpdateProgress.reopening.fraction, 1)
        for progress in steps {
            let data = try JSONEncoder().encode(progress)
            XCTAssertEqual(try JSONDecoder().decode(UpdateProgress.self, from: data), progress)
        }
    }
}


// MARK: - Release details
extension UpdateEngineTests {
    private func details(date: String?) -> UpdateDetails {
        UpdateDetails(version: "v2.1.0", downloadURL: URL(string: "https://example.com/Mac-Monitor.pkg")!,
                      releaseNotes: nil, releaseDate: date)
    }

    /// The version drops the tag's `v`, and the release day is the day in the given time zone.
    func testReleaseDayAndNumber() throws {
        let release = details(date: "2025-11-22T06:21:53Z")
        XCTAssertEqual(release.number, "2.1.0")
        let losAngeles = try XCTUnwrap(TimeZone(identifier: "America/Los_Angeles"))
        let utc = try XCTUnwrap(TimeZone(identifier: "UTC"))
        let pacificDay = try XCTUnwrap(release.releaseDay(in: losAngeles))
        let utcDay = try XCTUnwrap(release.releaseDay(in: utc))
        XCTAssertTrue(pacificDay.contains("21") && pacificDay.contains("2025"), pacificDay)
        XCTAssertTrue(utcDay.contains("22"), utcDay)
        XCTAssertNil(details(date: nil).releaseDay())
        XCTAssertNil(details(date: "November 21").releaseDay())
    }

    /// A heading loses its `#`s and is bold. A `#` without a space after it, inline Markdown and line breaks are kept,
    /// and GitHub's `\r\n` is one break.
    func testReleaseNotesHeadings() {
        let text = ReleaseNotesText.attributed("## Summary\r\nAdds `mprotect` and **more**\r\n\r\n#hashtag\n- item")
        XCTAssertEqual(String(text.characters), "Summary\nAdds mprotect and more\n\n#hashtag\n- item")
        let heading = text.runs.first { String(text[$0.range].characters) == "Summary" }
        XCTAssertEqual(heading?.inlinePresentationIntent, .stronglyEmphasized)
    }
}
