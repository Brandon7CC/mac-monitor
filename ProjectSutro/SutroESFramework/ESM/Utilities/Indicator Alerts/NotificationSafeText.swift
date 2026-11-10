//
//  NotificationSafeText.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Notification-safe text
/// Cleans text from an event for a notification, and caps its length. Any process picks its own executable's name and
/// the paths it writes, so they may hold controls that split a notification's lines, bidirectional characters that
/// show a path backwards, or zero-width characters that hide part of a name.
///
/// Lengths count Unicode scalars, as an indicator's own limits do (``Indicator/Limits``), so combining marks can't
/// stretch a line past its cap.
public enum NotificationSafeText {
    /// The zero-width characters: ZWSP, ZWNJ, ZWJ, WORD JOINER and the byte order mark.
    static let zeroWidth: Set<UInt32> = [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF]
    /// What ends a cut text.
    static let ellipsis: Unicode.Scalar = "\u{2026}"

    /// Text for a notification: newlines, tabs and other C0 and C1 controls (DEL too), and the LINE SEPARATOR and
    /// PARAGRAPH SEPARATOR that break a line as a newline does, become a space; the bidirectional and zero-width
    /// characters are removed, and runs of spaces become one, trimmed at both ends. Other non-ASCII text is kept.
    ///
    /// - Parameter text: Text from an event.
    /// - Returns: The cleaned text.
    public static func clean(_ text: String) -> String {
        var cleaned = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            let value = scalar.value
            if TerminalSafeText.bidiControls.contains(value) || zeroWidth.contains(value) { continue }
            let isControl = value < 0x20 || (0x7F...0x9F).contains(value) || value == 0x2028 || value == 0x2029
            let next: Unicode.Scalar = isControl ? " " : scalar
            if next == " ", cleaned.last == " " || cleaned.isEmpty { continue }
            cleaned.append(next)
        }
        if cleaned.last == " " { cleaned.removeLast() }
        return String(cleaned)
    }

    /// Cleaned text, cut at its end to a length.
    ///
    /// - Parameters:
    ///   - text: Text from an event.
    ///   - limit: The most scalars, the ellipsis included.
    /// - Returns: The cleaned text, ending in an ellipsis when it was cut.
    public static func truncated(_ text: String, to limit: Int) -> String {
        cut(clean(text), to: limit)
    }

    /// Text cut at its end to a length, as it is: for text already cleaned, such as a body's lines.
    ///
    /// - Parameters:
    ///   - text: The text.
    ///   - limit: The most scalars, the ellipsis included.
    /// - Returns: The text, ending in an ellipsis when it was cut.
    static func cut(_ text: String, to limit: Int) -> String {
        let scalars = text.unicodeScalars
        guard scalars.count > limit else { return text }
        var cut = String.UnicodeScalarView(scalars.prefix(max(0, limit - 1)))
        cut.append(ellipsis)
        return String(cut)
    }

    /// A cleaned path, cut in its middle to a length, so its start and its file name both show.
    ///
    /// - Parameters:
    ///   - path: A path from an event.
    ///   - limit: The most scalars, the ellipsis included.
    /// - Returns: The cleaned path, with an ellipsis in its middle when it was cut.
    public static func middleTruncated(_ path: String, to limit: Int) -> String {
        let scalars = Array(clean(path).unicodeScalars)
        guard scalars.count > limit else { return String(String.UnicodeScalarView(scalars)) }
        let kept = max(0, limit - 1)
        let head = kept / 2
        var cut = String.UnicodeScalarView(scalars.prefix(head))
        cut.append(ellipsis)
        cut.append(contentsOf: scalars.suffix(kept - head))
        return String(cut)
    }

    /// A path with the user's home folder shown as `~`.
    ///
    /// - Parameters:
    ///   - path: A path.
    ///   - home: The user's home folder, such as `/Users/brandon`.
    /// - Returns: `~/Library/...` for a path inside it, `~` for it, else the path.
    public static func abbreviatingHome(_ path: String, home: String) -> String {
        guard !home.isEmpty, home != "/" else { return path }
        if path == home { return "~" }
        let prefix = home.hasSuffix("/") ? home : home + "/"
        return path.hasPrefix(prefix) ? "~/" + path.dropFirst(prefix.count) : path
    }
}
