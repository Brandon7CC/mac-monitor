//
//  ReleaseVersion.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Release versions
/// A Mac Monitor release's version, such as 3.2.0: what an indicator pack names as the oldest Mac Monitor that can
/// run the pack, or one of its indicators. It's written, saved and shipped as a string of three numbers.
public struct ReleaseVersion: Comparable, Hashable, Codable, Sendable, CustomStringConvertible {
    public let major: Int
    public let minor: Int
    public let patch: Int

    /// - Parameters:
    ///   - major: The major version.
    ///   - minor: The minor version.
    ///   - patch: The patch version.
    public init(_ major: Int, _ minor: Int, _ patch: Int) {
        (self.major, self.minor, self.patch) = (major, minor, patch)
    }

    /// Read a version as a pack writes it.
    ///
    /// - Parameter text: Such as "3.2.0": exactly three dot-separated numbers, each one or more ASCII digits.
    /// - Returns: `nil` for anything else, such as "3.2", "v3.2.0" or "3.2.0-beta".
    public init?(_ text: String) {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        let numbers = parts.compactMap { part -> Int? in
            guard (1...9).contains(part.utf8.count), part.utf8.allSatisfy({ (0x30...0x39).contains($0) }) else {
                return nil
            }
            return Int(part)
        }
        guard parts.count == 3, numbers.count == 3 else { return nil }
        self.init(numbers[0], numbers[1], numbers[2])
    }

    /// Such as "3.2.0".
    public var description: String { "\(major).\(minor).\(patch)" }

    /// - Parameters:
    ///   - lhs: A version.
    ///   - rhs: Another.
    /// - Returns: Whether `lhs` is the earlier release.
    public static func < (lhs: ReleaseVersion, rhs: ReleaseVersion) -> Bool {
        (lhs.major, lhs.minor, lhs.patch) < (rhs.major, rhs.minor, rhs.patch)
    }

    /// Decode a version from its string.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: When it isn't a string of three numbers.
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)
        guard let version = ReleaseVersion(text) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: """
                '\(text)' isn't a Mac Monitor version, such as 3.2.0.
                """)
        }
        self = version
    }

    /// Encode a version as its string.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: When it can't be encoded.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}
