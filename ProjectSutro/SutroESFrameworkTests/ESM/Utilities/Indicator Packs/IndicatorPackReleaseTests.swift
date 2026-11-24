//
//  IndicatorPackReleaseTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/16/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Choosing a pack release
/// Pins which of the indicators repository's releases the Security Extension takes a pack from, what it remembers
/// about looking for one, and what each fetch error says.
final class IndicatorPackReleaseTests: XCTestCase {
    /// One of GitHub's releases.
    ///
    /// - Parameters:
    ///   - tag: Its tag.
    ///   - asset: Its asset's name, or `nil` for none.
    ///   - url: Where the asset downloads from.
    ///   - size: The asset's size.
    ///   - draft: Is it a draft?
    ///   - prerelease: Is it a prerelease?
    ///   - body: Its notes, or `nil` for a release GitHub gives none for.
    /// - Returns: The release, as GitHub's JSON has it.
    private func release(_ tag: String, asset: String? = IndicatorPackRelease.assetName,
                         url: String = "https://github.com/pack.json", size: Int = 1_000, draft: Bool = false,
                         prerelease: Bool = false, body: String? = "Notes.") -> [String: Any] {
        let assets: [[String: Any]] = asset.map { [["name": $0, "browser_download_url": url, "size": size]] } ?? []
        return ["tag_name": tag, "draft": draft, "prerelease": prerelease, "assets": assets,
                "body": body ?? NSNull()]
    }

    /// The newest pack in a listing.
    ///
    /// - Parameter releases: GitHub's releases.
    /// - Returns: The release chosen, or `nil`.
    /// - Throws: The chooser's error, or the error encoding the listing.
    private func newest(_ releases: [[String: Any]]) throws -> IndicatorPackRelease? {
        try IndicatorPackRelease.newest(in: try JSONSerialization.data(withJSONObject: releases), status: 200)
    }

    /// The release with the highest pack sequence is taken, wherever it is in the listing, as a number: pack 12 is
    /// later than pack 9.
    func testTheHighestSequenceIsTaken() throws {
        let chosen = try newest([release("pack-9"), release("pack-12", url: "https://github.com/12.json"),
                                 release("pack-2")])
        XCTAssertEqual(chosen, IndicatorPackRelease(sequence: 12,
                                                    download: try XCTUnwrap(URL(string: "https://github.com/12.json")),
                                                    notes: "Notes."))
        XCTAssertNil(try newest([]))
    }

    /// A release's notes come along, trimmed and cut to what's kept. A release that says nothing has none. Its page
    /// is the one its tag has on GitHub.
    func testAReleasesNotes() throws {
        XCTAssertEqual(try newest([release("pack-2", body: "\r\n## What's new\r\n- One\n\n")])?.notes,
                       "## What's new\r\n- One")
        for nothing in [nil, "", " \n\t"] {
            XCTAssertNil(try newest([release("pack-2", body: nothing)])?.notes)
        }
        let long = String(repeating: "é", count: IndicatorPackRelease.maxNotes + 50)
        XCTAssertEqual(try newest([release("pack-2", body: long)])?.notes?.count, IndicatorPackRelease.maxNotes)
        XCTAssertEqual(IndicatorPackRelease.page(of: 12).absoluteString,
                       "https://github.com/Brandon7CC/mac-monitor-indicators/releases/tag/pack-12")
    }

    /// A release that isn't a published pack release with a pack to download is passed over, so one never hides a
    /// pack: another kind of release, such as the benign corpus's, a draft, a prerelease, one without the pack's
    /// asset, one whose download isn't HTTPS, and one whose pack is larger than the Security Extension reads.
    func testOtherReleasesArePassedOver() throws {
        let others = [
            release("corpus-40"), release("v3.2.0"), release("pack-"), release("pack-07"), release("pack-1.5"),
            release("pack-9999999999"), release("PACK-50"), release("pack-30", draft: true),
            release("pack-31", prerelease: true), release("pack-32", asset: nil),
            release("pack-33", asset: "pack.json"), release("pack-34", url: "http://github.com/pack.json"),
            release("pack-35", size: IndicatorLimits.maxFileBytes + 1),
        ]
        XCTAssertNil(try newest(others))
        XCTAssertEqual(try newest(others + [release("pack-3")])?.sequence, 3)
        XCTAssertEqual(try newest([release("pack-4", size: IndicatorLimits.maxFileBytes)])?.sequence, 4)
    }

    /// An answer that isn't a 200, or isn't a list of releases, is an error, never "no newer pack".
    func testABadListingIsAnError() throws {
        let listing = try JSONSerialization.data(withJSONObject: [release("pack-3")])
        for status in [nil, 404, 403, 500] as [Int?] {
            XCTAssertEqual(thrown(IndicatorPackFetchError.self) {
                try IndicatorPackRelease.newest(in: listing, status: status)
            }, .listing(status: status))
        }
        for body in ["", "{}", #"{"message": "Not Found"}"#, "[7]"] {
            XCTAssertEqual(thrown(IndicatorPackFetchError.self) {
                try IndicatorPackRelease.newest(in: Data(body.utf8), status: 200)
            }, .unreadableListing, body)
        }
    }

    /// The update state reads back as it was written, but for why the last look failed, which isn't kept. What a
    /// file doesn't say is the default, and one this build doesn't read is no state.
    func testTheUpdateStateIsKept() throws {
        var updates = IndicatorPackUpdates()
        XCTAssertEqual(updates.mode, .notify)
        XCTAssertEqual(IndicatorPackUpdates(updates.encoded()), updates)
        updates.mode = .automatic
        updates.checked = Self.packDate("2026-11-16T21:00:00Z")
        updates.looked = Self.packDate("2026-11-16T09:00:00Z")
        updates.available = 3
        XCTAssertEqual(IndicatorPackUpdates(updates.encoded()), updates)
        updates.problem = "GitHub couldn't be reached."
        XCTAssertNil(IndicatorPackUpdates(updates.encoded())?.problem)

        let later = try XCTUnwrap(IndicatorPackUpdates(Data(#"{"version": 1, "mode": "nightly", "extra": 1}"#.utf8)))
        XCTAssertEqual(later, IndicatorPackUpdates())
        for file in ["", "[]", #"{"mode": "off"}"#, #"{"version": 2, "mode": "off"}"#, #"{"version": 0}"#] {
            XCTAssertNil(IndicatorPackUpdates(Data(file.utf8)), file)
        }
        XCTAssertEqual(IndicatorPackMode.allCases.map(\.rawValue), ["off", "notify", "auto"])
    }

    /// A look is due when the Security Extension never looked on its own, a day after its last look, and when the
    /// clock went back past it. When someone else had GitHub asked doesn't count. It's never due while the mode is
    /// off.
    func testWhenALookIsDue() {
        let now = Self.packClock
        var updates = IndicatorPackUpdates()
        XCTAssertTrue(updates.isDue(at: now))
        updates.checked = now
        XCTAssertTrue(updates.isDue(at: now), "Someone asked, but the daily look hasn't run")
        updates.looked = now
        XCTAssertFalse(updates.isDue(at: now))
        XCTAssertFalse(updates.isDue(at: now + IndicatorPackUpdates.checkInterval - 1))
        XCTAssertTrue(updates.isDue(at: now + IndicatorPackUpdates.checkInterval))
        XCTAssertTrue(updates.isDue(at: now - 1), "The clock went back")
        updates.mode = .automatic
        XCTAssertTrue(updates.isDue(at: now + IndicatorPackUpdates.checkInterval))
        updates.mode = .off
        XCTAssertFalse(updates.isDue(at: now + IndicatorPackUpdates.checkInterval))
        updates.looked = nil
        XCTAssertFalse(updates.isDue(at: now))
    }

    /// Each fetch error is a sentence the user reads.
    func testFetchErrorsAreSentences() {
        let sentences: [(IndicatorPackFetchError, String)] = [
            (.unreachable("The Internet connection appears to be offline."),
             "GitHub couldn't be reached. The Internet connection appears to be offline."),
            (.listing(status: 404), "GitHub answered 404 for the indicator packs' releases."),
            (.listing(status: nil), "GitHub's list of the indicator packs' releases couldn't be read."),
            (.unreadableListing, "GitHub's list of the indicator packs' releases couldn't be read."),
            (.download(status: 503), "GitHub answered 503 for the indicator pack's download."),
            (.download(status: nil), "The indicator pack couldn't be downloaded."),
            (.tooLarge, "The indicator pack's download is larger than 4 MiB."),
        ]
        for (error, sentence) in sentences {
            XCTAssertEqual(error.description, sentence)
        }
    }
}
