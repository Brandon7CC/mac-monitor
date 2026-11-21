//
//  IndicatorPackRelease.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/16/26.
//

import Foundation


// MARK: - Indicator pack release
/// Which release of the indicators repository holds the newest pack (Security Extension context).
///
/// The Security Extension reads the repository's releases from GitHub itself and takes the one with the highest
/// `pack-<sequence>` tag. A release for something else, such as a `corpus-<n>` one, a draft and a prerelease are
/// passed over, so publishing one never hides a pack. The pack is the release's asset named ``assetName``, and it's
/// only downloaded over HTTPS.
///
/// Nothing here is trusted. The tag only says which file to download: the pack's own signed sequence decides whether
/// it's installed (``IndicatorBaseline/replacement(from:)``). The release's notes are shown as text and nothing more.
public struct IndicatorPackRelease: Equatable, Sendable {
    /// The indicators repository's releases, newest first, as GitHub lists them.
    public static let releasesURL: URL =
        URL(string: "https://api.github.com/repos/Brandon7CC/mac-monitor-indicators/releases?per_page=100")!
    /// The name a release's pack has.
    public static let assetName = "mac-monitor-indicators.json"
    /// What a pack release's tag starts with, before its sequence.
    public static let tagPrefix = "pack-"
    /// How many characters of a release's notes are kept.
    public static let maxNotes = 16_384

    /// The sequence its tag names.
    public let sequence: Int
    /// Where its pack is downloaded from.
    public let download: URL
    /// What the release says of the pack on GitHub, cut to ``maxNotes`` characters. `nil` when it says nothing.
    /// Unlike the pack, it isn't signed.
    public let notes: String?

    /// - Parameters:
    ///   - sequence: The sequence its tag names.
    ///   - download: Where its pack is downloaded from.
    ///   - notes: What the release says of the pack.
    public init(sequence: Int, download: URL, notes: String? = nil) {
        self.sequence = sequence
        self.download = download
        self.notes = notes
    }

    /// A pack release's page on GitHub.
    ///
    /// - Parameter sequence: The pack's sequence.
    /// - Returns: The page.
    public static func page(of sequence: Int) -> URL {
        URL(string: "https://github.com/Brandon7CC/mac-monitor-indicators/releases/tag/\(tagPrefix)\(sequence)")!
    }

    /// The newest pack release in GitHub's listing.
    ///
    /// - Parameters:
    ///   - data: GitHub's answer for ``releasesURL``.
    ///   - status: The answer's HTTP status code, if it was an HTTP answer.
    /// - Returns: The release with the highest sequence that has a pack to download, or `nil` when none does.
    /// - Throws: ``IndicatorPackFetchError/listing(status:)`` for an answer that isn't a 200, and
    ///   ``IndicatorPackFetchError/unreadableListing`` for one that isn't a list of releases.
    public static func newest(in data: Data, status: Int?) throws(IndicatorPackFetchError) -> IndicatorPackRelease? {
        guard status == 200 else { throw .listing(status: status) }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        guard let releases = try? decoder.decode([Listed].self, from: data) else { throw .unreadableListing }
        return releases.compactMap(\.pack).max { $0.sequence < $1.sequence }
    }

    /// The sequence a tag names.
    ///
    /// - Parameter tag: A release's tag, such as "pack-12".
    /// - Returns: Such as 12, or `nil` unless it's ``tagPrefix`` and then one to nine ASCII digits with no leading
    ///   zero.
    static func sequence(of tag: String) -> Int? {
        guard tag.hasPrefix(tagPrefix) else { return nil }
        let digits = tag.dropFirst(tagPrefix.count).utf8
        guard (1...9).contains(digits.count), digits.first != 0x30,
              digits.allSatisfy({ (0x30...0x39).contains($0) }) else { return nil }
        return Int(tag.dropFirst(tagPrefix.count))
    }

    /// The fields read from one of GitHub's releases. The decoder converts GitHub's snake_case keys.
    private struct Listed: Decodable {
        /// A file attached to the release.
        struct Asset: Decodable {
            let name: String
            let browserDownloadUrl: URL
            /// The file's size in bytes, as GitHub says it.
            let size: Int?
        }

        let tagName: String
        let draft: Bool?
        let prerelease: Bool?
        let assets: [Asset]?
        /// The release's notes, as Markdown.
        let body: String?

        /// The pack this release holds, or `nil` when it isn't a published pack release with a pack to download
        /// over HTTPS that's no larger than the Security Extension reads.
        var pack: IndicatorPackRelease? {
            guard draft != true, prerelease != true, let sequence = IndicatorPackRelease.sequence(of: tagName),
                  let asset = assets?.first(where: { $0.name == IndicatorPackRelease.assetName }),
                  asset.browserDownloadUrl.scheme == "https",
                  (asset.size ?? 0) <= IndicatorLimits.maxFileBytes else { return nil }
            let notes = body?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return IndicatorPackRelease(sequence: sequence, download: asset.browserDownloadUrl,
                                        notes: notes.isEmpty ? nil : String(notes.prefix(maxNotes)))
        }
    }
}


// MARK: - Fetch errors
/// Why the newest pack couldn't be fetched from GitHub. Its description is a sentence the user reads.
public enum IndicatorPackFetchError: Error, Equatable, CustomStringConvertible {
    /// GitHub couldn't be reached: why, as the system says it.
    case unreachable(String)
    /// GitHub's list of releases didn't answer 200: the status it answered, if any.
    case listing(status: Int?)
    /// GitHub's answer isn't a list of releases.
    case unreadableListing
    /// The pack's download didn't answer 200: the status it answered, if any.
    case download(status: Int?)
    /// The pack's download is larger than ``IndicatorLimits/maxFileBytes``.
    case tooLarge

    /// What went wrong, as the user reads it.
    public var description: String {
        switch self {
        case .unreachable(let reason):
            "GitHub couldn't be reached. \(reason)"
        case .listing(let status?):
            "GitHub answered \(status) for the indicator packs' releases."
        case .listing(nil), .unreadableListing:
            "GitHub's list of the indicator packs' releases couldn't be read."
        case .download(let status?):
            "GitHub answered \(status) for the indicator pack's download."
        case .download(nil):
            "The indicator pack couldn't be downloaded."
        case .tooLarge:
            "The indicator pack's download is larger than \(IndicatorLimits.maxFileBytes >> 20) MiB."
        }
    }
}
