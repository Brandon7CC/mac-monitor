//
//  ReleaseChoice.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import OSLog


// MARK: - Release choice
/// Which GitHub release the Security Extension offers and installs (Security Extension context).
///
/// Nothing about the release comes from Mac Monitor: the Security Extension reads GitHub's latest release itself, and
/// keeps it only when its version is newer than the running one. Its package is the release's first asset whose name
/// ends in `.pkg`, and it's only downloaded over HTTPS.
public enum ReleaseChoice {
    /// GitHub's latest Mac Monitor release.
    public static let latestReleaseURL: URL =
        URL(string: "https://api.github.com/repos/Brandon7CC/mac-monitor/releases/latest")!

    private static let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension",
                                       category: "UpdateInstaller")

    /// The latest release, if it's newer than this build.
    ///
    /// - Parameters:
    ///   - data: GitHub's answer for ``latestReleaseURL``.
    ///   - status: The answer's HTTP status code, if it was an HTTP answer.
    ///   - current: The running version (`CFBundleShortVersionString`).
    /// - Returns: What Mac Monitor shows in its update sheet about the newer release, or `nil` if we're up-to-date.
    /// - Throws: ``UpdateError/releaseLookupFailed`` for an answer that isn't a 200, a release without a package, or
    ///   no running version, or why the release couldn't be read.
    public static func newer(in data: Data, status: Int?, than current: String?) throws -> UpdateDetails? {
        guard status == 200 else { throw UpdateError.releaseLookupFailed }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let release = try decoder.decode(GitHubRelease.self, from: data)

        guard let package = release.assets.first(where: \.isPackage)?.browserDownloadUrl, let current else {
            throw UpdateError.releaseLookupFailed
        }
        logger.log("""
            (Mac Monitor Update) Latest version found: \(release.version, privacy: .public). \
            Current version: \(current, privacy: .public)
            """)
        guard isNewer(release.tagName, than: current) else { return nil }
        return UpdateDetails(version: release.tagName, downloadURL: package, releaseNotes: release.body,
                             releaseDate: release.publishedAt)
    }

    /// Where a release's package may be downloaded from.
    ///
    /// - Parameter release: The release to install.
    /// - Returns: Its package's URL.
    /// - Throws: ``UpdateError/insecureDownload(_:)`` for a URL that isn't HTTPS.
    public static func download(of release: UpdateDetails) throws -> URL {
        guard release.downloadURL.scheme == "https" else { throw UpdateError.insecureDownload(release.downloadURL) }
        return release.downloadURL
    }

    /// Is a release's version newer than the running one?
    ///
    /// Both are read as dot-separated numbers, a tag's leading `v` dropped and missing parts read as 0, so "3.1.0" is
    /// the same release as "3.1", and "3.10.0" is newer than "3.9.9".
    ///
    /// - Parameters:
    ///   - version: The release's tag, such as "v3.1.0".
    ///   - current: The running version, such as "3.0.0".
    /// - Returns: `true` only if both read as versions and `version` is higher. A version that doesn't read, such as
    ///   "3.1.0-beta", is never newer.
    public static func isNewer(_ version: String, than current: String) -> Bool {
        guard let new = numbers(in: version), let old = numbers(in: current) else { return false }
        let length = max(new.count, old.count)
        let padded = { (parts: [Int]) in parts + Array(repeating: 0, count: length - parts.count) }
        return zip(padded(new), padded(old)).first { $0 != $1 }.map { $0 > $1 } ?? false
    }

    /// A version's numbers.
    ///
    /// - Parameter version: Such as "v3.1.0" or "3.1".
    /// - Returns: Such as `[3, 1, 0]`, or `nil` unless every part is one or more ASCII digits.
    static func numbers(in version: String) -> [Int]? {
        let parts = version.trimmingPrefix("v").split(separator: ".", omittingEmptySubsequences: false)
        let numbers = parts.compactMap { part -> Int? in
            guard !part.isEmpty, part.utf8.allSatisfy({ (0x30...0x39).contains($0) }) else { return nil }
            return Int(part)
        }
        return numbers.count == parts.count ? numbers : nil
    }
}


// MARK: - GitHub release
/// The fields Mac Monitor reads from GitHub's latest release. The decoder converts GitHub's snake_case keys.
struct GitHubRelease: Decodable {
    /// A file attached to the release. Releases also attach the telemetry schema.
    struct Asset: Decodable {
        let name: String
        let browserDownloadUrl: URL

        /// Is this the installer package?
        var isPackage: Bool { name.lowercased().hasSuffix(".pkg") }
    }

    let tagName: String
    let assets: [Asset]
    /// The release notes. GitHub sends `null` for a release without any.
    let body: String?
    /// When the release was published. `null` for a draft.
    let publishedAt: String?

    /// The release version without the tag's `v` prefix.
    var version: String { String(tagName.trimmingPrefix("v")) }
}
