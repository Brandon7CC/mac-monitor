//
//  FlowURL.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - A flow's URL
/// The URL a flow's request named, made safe to record. The value is the process's own, so nothing is assumed of
/// it. Only `http` and `https` are kept, never a user and password, a query or a fragment, and a path segment shaped
/// like a secret becomes `<redacted>`, so the path keeps its structure.
enum FlowURL {
    /// The longest URL kept, in UTF-8 bytes.
    static let limit = 2_048
    /// What a redacted segment, or the token of a Telegram bot's, becomes.
    static let redacted = "<redacted>"

    /// A URL to record.
    ///
    /// - Parameters:
    ///   - raw: The URL as the process gave it.
    ///   - keepingPath: Keep the path? Without it the URL ends at the host and port.
    /// - Returns: The URL, or `nil` when it isn't `http` or `https` or names no host.
    static func sanitized(_ raw: String, keepingPath: Bool) -> String? {
        guard let schemeEnd = raw.range(of: "://") else { return nil }
        let scheme = raw[..<schemeEnd.lowerBound].lowercased()
        guard scheme == "http" || scheme == "https" else { return nil }
        let rest = raw[schemeEnd.upperBound...].prefix { $0 != "?" && $0 != "#" }
        let pathStart = rest.firstIndex(of: "/") ?? rest.endIndex
        var authority = rest[..<pathStart]
        if let at = authority.lastIndex(of: "@") { authority = authority[authority.index(after: at)...] }
        guard !authority.isEmpty else { return nil }
        var url = scheme + "://" + authority
        if keepingPath {
            let segments = rest[pathStart...].split(separator: "/", omittingEmptySubsequences: false)
            url += redacting(segments.map(String.init)).joined(separator: "/")
        }
        return limited(url)
    }

    /// A path with each secret-shaped segment redacted.
    ///
    /// - Parameter segments: The path's segments. The first is empty, since the path starts with `/`.
    /// - Returns: The segments.
    static func redacting(_ segments: [String]) -> [String] {
        var segments = segments.map { botToken($0) ?? (isSecret($0) ? redacted : $0) }
        /// Is a segment this name?
        ///
        /// - Parameters:
        ///   - index: The segment's index.
        ///   - name: The name.
        /// - Returns: Whether there's a segment at the index with the name.
        func named(_ index: Int, _ name: String) -> Bool {
            segments.indices.contains(index) && segments[index] == name
        }
        // A Slack webhook, `/services/<team>/<bot>/<secret>`.
        if named(1, "services"), segments.count > 4 { segments[4] = redacted }
        // A Discord webhook, `/api/webhooks/<id>/<token>` or `/api/v<N>/webhooks/<id>/<token>`.
        if named(1, "api"), let hook = [2, 3].first(where: { named($0, "webhooks") }), segments.count > hook + 2,
           hook == 2 || segments[2].first == "v" {
            segments[hook + 2] = redacted
        }
        return segments
    }

    /// A Telegram bot's segment with its token redacted.
    ///
    /// - Parameter segment: A path segment.
    /// - Returns: `bot<digits>:<redacted>` for `bot<digits>:<token>`, otherwise `nil`.
    private static func botToken(_ segment: String) -> String? {
        guard segment.hasPrefix("bot"), let colon = segment.firstIndex(of: ":") else { return nil }
        let digits = segment.dropFirst(3)[..<colon]
        guard !digits.isEmpty, digits.allSatisfy(\.isASCIIDigit), segment[colon...].count > 1 else { return nil }
        return "bot\(digits):\(redacted)"
    }

    /// Is a segment shaped like a secret? A JWT (`eyJ`, then two dots), 32 or more hex digits, or 32 or more URL-safe
    /// Base64 characters with an upper-case letter, a lower-case letter and a digit.
    ///
    /// - Parameter segment: A path segment.
    /// - Returns: Whether it is.
    static func isSecret(_ segment: String) -> Bool {
        if segment.hasPrefix("eyJ"), segment.filter({ $0 == "." }).count == 2 { return true }
        guard segment.utf8.count >= 32 else { return false }
        if segment.allSatisfy({ $0.isASCII && $0.isHexDigit }) { return true }
        let safe = segment.allSatisfy { $0.isASCIIDigit || $0.isASCIILetter || $0 == "-" || $0 == "_" }
        return safe && segment.contains(where: \.isUppercase) && segment.contains(where: \.isLowercase)
            && segment.contains(where: \.isASCIIDigit)
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


private extension Character {
    /// Is it `0` to `9`?
    var isASCIIDigit: Bool { isASCII && isWholeNumber }
    /// Is it `A` to `Z` or `a` to `z`?
    var isASCIILetter: Bool { isASCII && isLetter }
}
