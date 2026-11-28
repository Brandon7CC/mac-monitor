//
//  FlowURL.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - A flow's URL
/// The URL a flow's request named, as the process gave it. Nothing in it is redacted or taken out. Only an `http` or
/// `https` URL that names a host is kept, cut to ``limit`` bytes.
enum FlowURL {
    /// The longest URL kept, in UTF-8 bytes.
    static let limit = 2_048

    /// A URL to record.
    ///
    /// - Parameters:
    ///   - raw: The URL as the process gave it.
    ///   - keepingPath: Keep what follows the host and port? Without it the URL ends there.
    /// - Returns: The URL, or `nil` when it isn't `http` or `https` or names no host.
    static func recorded(_ raw: String, keepingPath: Bool) -> String? {
        guard let schemeEnd = raw.range(of: "://") else { return nil }
        let scheme = raw[..<schemeEnd.lowerBound].lowercased()
        guard scheme == "http" || scheme == "https" else { return nil }
        let rest = raw[schemeEnd.upperBound...]
        let authorityEnd = rest.firstIndex { "/?#".contains($0) } ?? rest.endIndex
        let host = rest[..<authorityEnd].split(separator: "@", omittingEmptySubsequences: false).last ?? ""
        guard !host.isEmpty else { return nil }
        return limited(keepingPath ? raw : String(raw[..<authorityEnd]))
    }

    /// - Parameter url: A URL.
    /// - Returns: The URL cut at a scalar's end to ``limit`` UTF-8 bytes.
    private static func limited(_ url: String) -> String {
        guard url.utf8.count > limit else { return url }
        var kept = String.UnicodeScalarView(), bytes = 0
        for scalar in url.unicodeScalars {
            bytes += UTF8.width(scalar)
            guard bytes <= limit else { break }
            kept.append(scalar)
        }
        return String(kept)
    }
}
