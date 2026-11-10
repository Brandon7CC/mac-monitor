//
//  PredicateSyntax.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import AppKit
import SutroESFramework


// MARK: - Syntax
/// How a predicate's text is colored, as Xcode colors code, in light and dark.
enum PredicateSyntax {
    static let font = monospaced(size: 12)
    static let boldFont = monospaced(size: 12, weight: .semibold)
    static let keyColor = dynamic(light: 0x0F68A0, dark: 0x67B7A4)
    static let keywordColor = dynamic(light: 0x9B2393, dark: 0xFC5FA3)
    static let stringColor = dynamic(light: 0xC41A16, dark: 0xFC6A5D)
    static let numberColor = dynamic(light: 0x1C00CF, dark: 0xD0BF69)
    static let variableColor = dynamic(light: 0x6C36A9, dark: 0xA167E6)
    static let commentColor = dynamic(light: 0x5D6C79, dark: 0x6C7986)

    /// - Parameters:
    ///   - size: The text's size, in points.
    ///   - weight: Its weight, regular for the text and semibold for keywords.
    /// - Returns: The monospaced font a predicate is in.
    static func monospaced(size: CGFloat, weight: NSFont.Weight = .regular) -> NSFont {
        NSFont.monospacedSystemFont(ofSize: size, weight: weight)
    }

    /// Color a predicate's text, and underline each key path from its first key that isn't where it puts it, as the
    /// predicate is refused for it.
    ///
    /// - Parameters:
    ///   - storage: The predicate's text, such as the editor's.
    ///   - size: The text's size, in points: 12 in the editor.
    static func highlight(_ storage: NSTextStorage, size: CGFloat = 12) {
        let font = monospaced(size: size)
        let boldFont = monospaced(size: size, weight: .semibold)
        let full = NSRange(location: 0, length: storage.length)
        storage.beginEditing()
        storage.setAttributes([.font: font, .foregroundColor: NSColor.labelColor], range: full)
        for token in PredicateText.tokens(in: storage.string) {
            switch token.kind {
            case .string: storage.addAttribute(.foregroundColor, value: stringColor, range: token.range)
            case .number: storage.addAttribute(.foregroundColor, value: numberColor, range: token.range)
            case .comparison, .function: storage.addAttribute(.foregroundColor, value: keywordColor, range: token.range)
            case .keyword:
                storage.addAttributes([.foregroundColor: keywordColor, .font: boldFont], range: token.range)
            case .keyPath, .variable:
                storage.addAttribute(.foregroundColor, value: keyColor, range: token.range)
                let keys = PredicateText.keys(of: token)
                var offset = token.range.location
                /// `$e`, a SUBQUERY's related event, then its keys.
                if token.kind == .variable {
                    /// `$e.` before the keys, or all of a `$e` alone.
                    let length = (token.text as NSString).length
                        - (keys.isEmpty ? -1 : (keys.joined(separator: ".") as NSString).length)
                    storage.addAttributes([.foregroundColor: variableColor, .font: boldFont],
                                          range: NSRange(location: offset, length: length - 1))
                    offset += length
                }
                /// Related events, which a SUBQUERY goes through, are where they should be on their own.
                let valid = token.kind == .keyPath && keys.count == 1 && PredicateRelation(rawValue: keys[0]) != nil
                    ? keys.count : RecordKeyPaths.shared.validCount(of: keys)
                for (index, key) in keys.enumerated() {
                    let range = NSRange(location: offset, length: (key as NSString).length)
                    if index >= valid {
                        storage.addAttributes([.foregroundColor: NSColor.labelColor,
                                               .underlineStyle: NSUnderlineStyle.thick.union(.patternDot).rawValue,
                                               .underlineColor: NSColor.systemRed], range: range)
                    }
                    offset += range.length + 1
                }
            }
        }
        storage.endEditing()
    }

    /// - Parameters:
    ///   - light: The color in light mode, as 0xRRGGBB.
    ///   - dark: In dark mode.
    /// - Returns: A color that follows the appearance.
    private static func dynamic(light: Int, dark: Int) -> NSColor {
        .appearance(light: .hex(light), dark: .hex(dark))
    }
}

