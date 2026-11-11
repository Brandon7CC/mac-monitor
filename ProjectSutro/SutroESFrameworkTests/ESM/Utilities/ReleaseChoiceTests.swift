//
//  ReleaseChoiceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Which release the Security Extension installs
/// Pins which GitHub release the Security Extension offers and installs as root: only one whose version is higher
/// than the running one, its first `.pkg` asset, and only over HTTPS. A lookup that failed is never "up to date".
final class ReleaseChoiceTests: XCTestCase {
    /// Where a release asset is downloaded from.
    ///
    /// - Parameter name: The asset's name.
    /// - Returns: Its URL on GitHub.
    private func download(_ name: String) -> String {
        "https://github.com/Brandon7CC/mac-monitor/releases/download/v3.1.0/\(name)"
    }

    /// GitHub's answer for the latest release, with only the keys Mac Monitor reads plus one it doesn't.
    ///
    /// - Parameters:
    ///   - tag: The release's tag.
    ///   - assets: Each asset's name and download URL, in order.
    ///   - body: The release notes, or `nil` for GitHub's `null`.
    ///   - publishedAt: When it was published, or `nil` for GitHub's `null`.
    /// - Returns: The JSON.
    /// - Throws: If it can't be encoded.
    private func release(tag: String = "v3.1.0", assets: [(String, String)]? = nil, body: String? = "## Changes",
                         publishedAt: String? = "2026-11-20T18:00:00Z") throws -> Data {
        let assets = assets ?? [("mac-monitor-telemetry.schema.json", download("mac-monitor-telemetry.schema.json")),
                                ("Mac-Monitor.pkg", download("Mac-Monitor.pkg"))]
        let object: [String: Any] = [
            "tag_name": tag,
            "name": "Mac Monitor \(tag)",
            "assets": assets.map { ["name": $0.0, "browser_download_url": $0.1, "size": 1] },
            "body": body ?? NSNull(),
            "published_at": publishedAt ?? NSNull(),
        ]
        return try JSONSerialization.data(withJSONObject: object)
    }

    /// The release offered over a running version.
    ///
    /// - Parameters:
    ///   - data: GitHub's answer.
    ///   - current: The running version.
    /// - Returns: The release, or `nil` for none newer.
    /// - Throws: Why the release couldn't be chosen.
    private func offered(_ data: Data, over current: String? = "3.0.0") throws -> UpdateDetails? {
        try ReleaseChoice.newer(in: data, status: 200, than: current)
    }

    /// Versions compare part by part as numbers, missing parts reading as 0, so a release that only writes its version
    /// differently is the same release. A version that isn't dot-separated numbers is never newer.
    func testVersionsCompareAsNumbers() {
        let cases: [(version: String, current: String, newer: Bool)] = [
            ("3.1.0", "3.1", false),
            ("3.1", "3.1.0", false),
            ("3.1.0.0", "3.1", false),
            ("3.01.0", "3.1.0", false),
            ("3.10.0", "3.9.9", true),
            ("3.9.9", "3.10.0", false),
            ("3.1.0", "3.1.0", false),
            ("v3.1.0", "3.1.0", false),
            ("3.0.0", "3.1.0", false),
            ("2.9.9", "3.0.0", false),
            ("v3.1.1", "3.1.0", true),
            ("3.1.0.1", "3.1", true),
            ("4", "3.99.99", true),
            ("v3.2", "3.1.9", true),
            ("3.1.0-beta", "3.1.0", false),
            ("3.2.0-beta", "3.1.0", false),
            ("V3.2.0", "3.1.0", false),
            ("vv3.2.0", "3.1.0", false),
            (" 3.2.0", "3.1.0", false),
            ("3..2", "3.1.0", false),
            ("3.2.", "3.1.0", false),
            ("", "3.1.0", false),
            ("3.\u{0662}", "3.1.0", false),
            ("3.99999999999999999999", "3.1.0", false),
            ("3.2.0", "", false),
            ("3.2.0", "unknown", false),
        ]
        for (version, current, newer) in cases {
            XCTAssertEqual(ReleaseChoice.isNewer(version, than: current), newer, "\(version) over \(current)")
        }
    }

    /// A newer release is offered with its tag, its package, its notes and its date, as GitHub gave them.
    func testANewerReleaseIsOffered() throws {
        let details = try XCTUnwrap(try offered(try release()))
        XCTAssertEqual(details.version, "v3.1.0")
        XCTAssertEqual(details.number, "3.1.0")
        XCTAssertEqual(details.downloadURL, URL(string: download("Mac-Monitor.pkg")))
        XCTAssertEqual(details.releaseNotes, "## Changes")
        XCTAssertEqual(details.releaseDate, "2026-11-20T18:00:00Z")

        let bare = try XCTUnwrap(try offered(try release(body: nil, publishedAt: nil)))
        XCTAssertNil(bare.releaseNotes)
        XCTAssertNil(bare.releaseDate)
    }

    /// The same release, written either way, and an older one are up to date.
    func testTheSameOrAnOlderReleaseIsUpToDate() throws {
        for (tag, current) in [("v3.1.0", "3.1.0"), ("v3.1.0", "3.1"), ("v3.1", "3.1.0"), ("v3.0.0", "3.1.0"),
                               ("v3.1.0-rc1", "3.1.0")] {
            XCTAssertNil(try offered(try release(tag: tag), over: current), "\(tag) over \(current)")
        }
    }

    /// The package is the first asset whose name ends in `.pkg`, in any case. A release without one isn't offered.
    func testThePackageIsTheFirstPkgAsset() throws {
        let assets = [("Mac-Monitor.pkg.zip", download("zip")), ("notes-pkg", download("notes")),
                      ("Mac-Monitor.PKG", download("first")), ("Other.pkg", download("second"))]
        XCTAssertEqual(try offered(try release(assets: assets))?.downloadURL, URL(string: download("first")))

        for assets: [(String, String)] in [[], [("mac-monitor-telemetry.schema.json", download("schema"))],
                       [("Mac-Monitor.pkg.zip", download("zip"))]] {
            XCTAssertEqual(thrown(UpdateError.self) { try offered(try release(assets: assets)) }, .releaseLookupFailed)
        }
    }

    /// A lookup GitHub didn't answer with a 200, or without a running version to compare, fails, rather than reading
    /// as up to date. An answer that isn't a release throws why.
    func testAFailedLookupIsNotUpToDate() throws {
        let data = try release()
        for status in [nil, 403, 404, 500, 204] as [Int?] {
            let failure = thrown(UpdateError.self) { try ReleaseChoice.newer(in: data, status: status, than: "3.0.0") }
            XCTAssertEqual(failure, .releaseLookupFailed, "\(String(describing: status))")
        }
        XCTAssertEqual(thrown(UpdateError.self) { try offered(data, over: nil) }, .releaseLookupFailed)
        XCTAssertNotNil(thrown(DecodingError.self) { try offered(Data(#"{"message":"Not Found"}"#.utf8)) })
        XCTAssertNotNil(thrown(DecodingError.self) { try offered(Data("<html>".utf8)) })
    }

    /// The package is downloaded only over HTTPS.
    func testOnlyHTTPSDownloads() throws {
        let secure = try XCTUnwrap(try offered(try release()))
        XCTAssertEqual(try ReleaseChoice.download(of: secure), secure.downloadURL)

        for link in ["http://github.com/a.pkg", "ftp://github.com/a.pkg", "file:///private/tmp/a.pkg",
                     "//github.com/a.pkg"] {
            let insecure = try XCTUnwrap(try offered(try release(assets: [("Mac-Monitor.pkg", link)])), link)
            let url = try XCTUnwrap(URL(string: link))
            XCTAssertEqual(thrown(UpdateError.self) { try ReleaseChoice.download(of: insecure) },
                           .insecureDownload(url), link)
        }
    }

    /// The Security Extension asks GitHub, over HTTPS, for Mac Monitor's latest release.
    func testTheLookupGoesToGitHub() {
        XCTAssertEqual(ReleaseChoice.latestReleaseURL.absoluteString,
                       "https://api.github.com/repos/Brandon7CC/mac-monitor/releases/latest")
    }
}
