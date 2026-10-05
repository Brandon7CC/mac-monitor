//
//  TerminalSafeText.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Terminal-safe text
/// Escapes what event data could use to drive a terminal: a file named with an escape sequence, or a command line that
/// reverses the text after it.
///
/// Any process can put control characters in its arguments or file names, and `macmonitor` writes them to root's
/// terminal. So text output escapes every C0 control (newlines and tabs included, so each event stays one line), DEL,
/// every C1 control, and the bidirectional formatting characters. JSON written to a terminal escapes DEL, C1 and the
/// bidirectional characters as `\uXXXX`; `JSONEncoder` already escapes C0. JSON piped elsewhere is left byte for byte
/// as the export writes it.
public enum TerminalSafeText {
    /// The bidirectional formatting characters: ALM, LRM, RLM, LRE to RLO, and LRI to PDI.
    static let bidiControls: Set<UInt32> = [0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
                                            0x2066, 0x2067, 0x2068, 0x2069]
    
    /// Text for a terminal: `\n`, `\r` and `\t` as such, other C0 controls and DEL as `\x1B`, and C1 and bidirectional
    /// controls as `\u{202E}`. Everything else, other non-ASCII text included, is kept.
    ///
    /// - Parameter text: Text from an event.
    /// - Returns: The text, safe to print.
    public static func text(_ text: String) -> String {
        guard text.unicodeScalars.contains(where: needsEscape) else { return text }
        var escaped = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\n": escaped.append(contentsOf: #"\n"#.unicodeScalars)
            case "\r": escaped.append(contentsOf: #"\r"#.unicodeScalars)
            case "\t": escaped.append(contentsOf: #"\t"#.unicodeScalars)
            case _ where scalar.value < 0x20 || scalar.value == 0x7F:
                escaped.append(contentsOf: "\\x\(hex(scalar.value, digits: 2))".unicodeScalars)
            case _ where needsEscape(scalar):
                escaped.append(contentsOf: "\\u{\(hex(scalar.value, digits: 2))}".unicodeScalars)
            default:
                escaped.append(scalar)
            }
        }
        return String(escaped)
    }
    
    /// JSON for a terminal: DEL, C1 controls and bidirectional controls in its strings become `\uXXXX` escapes. The
    /// JSON stays valid and means the same: those characters can only appear inside strings.
    ///
    /// - Parameter json: UTF-8 JSON, such as an export line.
    /// - Returns: The JSON, safe to print.
    public static func json(_ json: Data) -> Data {
        guard json.contains(where: { $0 >= 0x7F }) else { return json }
        var escaped = Data(capacity: json.count + 32)
        var scalars = String(decoding: json, as: UTF8.self).unicodeScalars.makeIterator()
        while let scalar = scalars.next() {
            /// C0 is left alone: `JSONEncoder` escaped it in strings, and the line's own newline must stay one.
            if scalar.value >= 0x7F && needsEscape(scalar) {
                escaped.append(contentsOf: "\\u\(hex(scalar.value, digits: 4))".utf8)
            } else {
                escaped.append(contentsOf: String(scalar).utf8)
            }
        }
        return escaped
    }
    
    /// Is a character one a terminal could act on?
    ///
    /// - Parameter scalar: The character.
    /// - Returns: `true` for C0 controls, DEL, C1 controls, and the bidirectional controls.
    static func needsEscape(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value < 0x20 || (0x7F...0x9F).contains(scalar.value) || bidiControls.contains(scalar.value)
    }
    
    /// A number in uppercase hexadecimal.
    ///
    /// - Parameters:
    ///   - value: The number.
    ///   - digits: The fewest digits, padded with zeros.
    /// - Returns: The digits.
    private static func hex(_ value: UInt32, digits: Int) -> String {
        let text = String(value, radix: 16, uppercase: true)
        return String(repeating: "0", count: max(0, digits - text.count)) + text
    }
}
