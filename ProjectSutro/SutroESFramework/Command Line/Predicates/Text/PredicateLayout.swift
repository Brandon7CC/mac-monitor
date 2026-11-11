//
//  PredicateLayout.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Predicate layout
/// A predicate laid out to read, as Event Facts' Indicators popover shows one: a condition a line. Each `AND` and `OR`
/// (or `&&` and `||`) starts a line, those of the whole predicate indented a level under its first condition. A group
/// with an `AND` or `OR` in it opens at the end of its line, has its conditions a level deeper, each on its own line,
/// and closes on a line of its own, back at the level it opened at. A group without, such as
/// `(ANY env BEGINSWITH "DYLD_")` or `NOT (a == 1)`, stays on its line, as do a function's arguments, such as a
/// `SUBQUERY`'s, and quoted strings.
///
/// Lines only break where the predicate has room for it, so joining them again as they were joined
/// (``oneLine``) gives the predicate back exactly.
public struct PredicateLayout: Equatable {
    /// A line of the layout.
    public struct Line: Equatable {
        /// How many levels it's indented.
        public let depth: Int
        /// Its text, without its indentation.
        public let text: String
        /// What joined it to the line before in the predicate: a space, or nothing after `(` and before `)`.
        public let joint: String

        /// - Parameters:
        ///   - depth: How many levels it's indented.
        ///   - text: Its text, without its indentation.
        ///   - joint: What joined it to the line before in the predicate.
        public init(depth: Int, text: String, joint: String = " ") {
            self.depth = depth
            self.text = text
            self.joint = joint
        }
    }

    /// The spaces each level indents.
    public static let indentWidth = 2

    /// The lines, in order.
    public let lines: [Line]

    /// Lay out a predicate. It's put on one line first (``oneLine(_:)``), so it's laid out the same however it was
    /// written.
    ///
    /// - Parameter predicate: A predicate's text.
    public init(_ predicate: String) {
        let text = Self.oneLine(predicate)
        lines = LayoutBuilder(text).lines()
    }

    /// The lines, each indented ``indentWidth`` spaces a level, a line break between each two.
    public var text: String {
        lines.map { String(repeating: " ", count: $0.depth * Self.indentWidth) + $0.text }.joined(separator: "\n")
    }

    /// The predicate on one line, the lines joined as they were: what Copy puts on the pasteboard.
    public var oneLine: String {
        lines.enumerated().map { $0.offset == 0 ? $0.element.text : $0.element.joint + $0.element.text }.joined()
    }

    /// A predicate on one line: each run of whitespace outside a quoted string that breaks a line becomes a space, or
    /// nothing after `(` and before `)`, and the ends are trimmed. A predicate already on one line comes back as it is.
    ///
    /// - Parameter predicate: A predicate's text, on one line or several.
    /// - Returns: It on one line.
    public static func oneLine(_ predicate: String) -> String {
        var out = ""
        var quote: Character?
        var escaped = false
        var run = ""
        for character in predicate {
            if let open = quote {
                out.append(character)
                if escaped { escaped = false } else if character == "\\" { escaped = true } else if character == open {
                    quote = nil
                }
                continue
            }
            if character.isWhitespace {
                run.append(character)
                continue
            }
            if !run.isEmpty {
                out += Self.joint(for: run, after: out.last, before: character)
                run = ""
            }
            if character == "\"" || character == "'" { quote = character }
            out.append(character)
        }
        return out.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// - Parameters:
    ///   - run: A run of whitespace outside a quoted string.
    ///   - previous: The character before it, if any.
    ///   - next: The character after it.
    /// - Returns: The run as it is on one line, or what replaces it when it breaks a line.
    private static func joint(for run: String, after previous: Character?, before next: Character) -> String {
        guard run.contains(where: \.isNewline) else { return run }
        return previous == nil || previous == "(" || next == ")" ? "" : " "
    }
}


// MARK: - Building
/// Finds where a predicate on one line breaks into ``PredicateLayout``'s lines: it reads the predicate's tokens
/// (``PredicateText/tokens(in:)``) and its parentheses into groups, then walks them.
private struct LayoutBuilder {
    /// A part of the predicate: a token, or a group in parentheses.
    enum Item {
        case token(PredicateText.Token)
        case group(Group)
    }

    /// Parentheses and what's between them.
    struct Group {
        /// Where its `(` is, or `nil` for the whole predicate.
        var open: Int?
        /// Where its `)` is, or `nil` when it isn't closed.
        var close: Int?
        /// A function's arguments, such as `SUBQUERY(...)`'s, rather than a group of conditions?
        var isCall = false
        var items: [Item] = []

        /// Does it break into lines: a group of conditions with an `AND` or `OR` in it, or in a group in it that
        /// does?
        var breaksLines: Bool {
            !isCall && items.contains { item in
                switch item {
                case .token(let token): return LayoutBuilder.isJoiner(token)
                case .group(let group): return group.breaksLines
                }
            }
        }
    }

    /// Where a line breaks: the whitespace it takes the place of, and the next line's depth.
    struct Break {
        let range: NSRange
        let depth: Int
    }

    /// Keywords that may come right before the `(` of a group of conditions, which aren't function names.
    private static let operators: Set<String> = ["AND", "OR", "NOT", "ANY", "ALL", "NONE", "SOME", "IN"]
    /// What joins conditions: the keywords, in any case, and their symbols.
    private static let joiners: Set<String> = ["AND", "OR", "&&", "||"]

    let text: NSString
    private var breaks: [Break] = []
    /// The depth of the line being built.
    private var depth = 0

    /// - Parameter text: A predicate on one line.
    init(_ text: String) {
        self.text = text as NSString
    }

    /// - Returns: The predicate's lines.
    func lines() -> [PredicateLayout.Line] {
        guard text.length > 0 else { return [] }
        var builder = self
        builder.walk(Self.root(of: text), continuation: 1)
        var lines: [PredicateLayout.Line] = []
        var start = 0
        var depth = 0
        var joint = ""
        for line in builder.breaks {
            lines.append(.init(depth: depth, text: text.substring(with: NSRange(start ..< line.range.location)),
                               joint: joint))
            joint = text.substring(with: line.range)
            start = NSMaxRange(line.range)
            depth = line.depth
        }
        lines.append(.init(depth: depth, text: text.substring(from: start), joint: joint))
        return lines
    }

    /// - Parameter token: A token.
    /// - Returns: Does it join conditions, as `AND`, `OR`, `&&` and `||` do? An `AND` or `OR` written right before
    ///   `(` is read as a function, so it counts too.
    static func isJoiner(_ token: PredicateText.Token) -> Bool {
        [.keyword, .function].contains(token.kind) && joiners.contains(token.text.uppercased())
    }

    /// - Parameter token: The token before a `(`, past any whitespace, if any.
    /// - Returns: Does the `(` open a function's arguments, as after `SUBQUERY` or `lowercase`, rather than a group of
    ///   conditions?
    private static func isCall(after token: PredicateText.Token?) -> Bool {
        guard let token, [.keyPath, .function].contains(token.kind) else { return false }
        return !operators.contains(token.text.uppercased())
    }

    // MARK: Walking
    /// Break a group's lines: before each `AND` and `OR` after its first condition, at the depth its conditions go
    /// on, and around each group in it that breaks.
    ///
    /// - Parameters:
    ///   - group: The group.
    ///   - continuation: The depth of its lines that start with `AND` or `OR`.
    private mutating func walk(_ group: Group, continuation: Int) {
        for (index, item) in group.items.enumerated() {
            switch item {
            case .token(let token) where index > 0 && Self.isJoiner(token):
                breakLine(before: token.range.location, depth: continuation)
            case .group(let inner) where inner.breaksLines:
                let opened = depth
                if let open = inner.open { breakLine(after: open, depth: opened + 1) }
                walk(inner, continuation: opened + 1)
                if let close = inner.close { breakLine(before: close, depth: opened) }
            default:
                continue
            }
        }
    }

    /// Break the line before a place, taking the whitespace before it.
    ///
    /// - Parameters:
    ///   - location: The place, which starts the next line.
    ///   - depth: The next line's depth.
    private mutating func breakLine(before location: Int, depth: Int) {
        var start = location
        while start > 0, isWhitespace(at: start - 1) { start -= 1 }
        add(Break(range: NSRange(start ..< location), depth: depth))
    }

    /// Break the line after a place, taking the whitespace after it.
    ///
    /// - Parameters:
    ///   - location: The place, which ends the line.
    ///   - depth: The next line's depth.
    private mutating func breakLine(after location: Int, depth: Int) {
        var end = location + 1
        while end < text.length, isWhitespace(at: end) { end += 1 }
        add(Break(range: NSRange(location + 1 ..< end), depth: depth))
    }

    /// Keep a break, unless it's at an end of the predicate or right after the one before, which would leave a line
    /// empty.
    ///
    /// - Parameter line: The break.
    private mutating func add(_ line: Break) {
        guard line.range.location > 0, NSMaxRange(line.range) < text.length,
              line.range.location > breaks.last.map({ NSMaxRange($0.range) }) ?? 0 else { return }
        breaks.append(line)
        depth = line.depth
    }

    /// - Parameter location: A place in the predicate.
    /// - Returns: Is the character there whitespace?
    private func isWhitespace(at location: Int) -> Bool {
        Self.isWhitespace(text.character(at: location))
    }

    // MARK: Reading
    /// - Parameter text: A predicate on one line.
    /// - Returns: The whole predicate as a group: its tokens, `&&` and `||` as tokens too, and its parentheses as
    ///   groups. A `)` with no `(` is left out, and a `(` with no `)` holds the rest.
    private static func root(of text: NSString) -> Group {
        var stack = [Group()]
        /// The token before, past any whitespace: `nil` after anything else.
        var previous: PredicateText.Token?
        var location = 0
        for token in PredicateText.tokens(in: text as String).map(Optional.some) + [nil] {
            let end = token?.range.location ?? text.length
            while location < end {
                let character = text.character(at: location)
                switch character {
                case 0x28:
                    stack.append(Group(open: location, isCall: isCall(after: previous)))
                case 0x29 where stack.count > 1:
                    var closed = stack.removeLast()
                    closed.close = location
                    stack[stack.count - 1].items.append(.group(closed))
                case 0x26, 0x7C:
                    guard location + 1 < end, text.character(at: location + 1) == character else { break }
                    let range = NSRange(location: location, length: 2)
                    let symbol = PredicateText.Token(kind: .keyword, text: text.substring(with: range), range: range)
                    stack[stack.count - 1].items.append(.token(symbol))
                    location += 1
                default:
                    break
                }
                if !isWhitespace(character) { previous = nil }
                location += 1
            }
            guard let token else { break }
            stack[stack.count - 1].items.append(.token(token))
            previous = token
            location = NSMaxRange(token.range)
        }
        while stack.count > 1 {
            let unclosed = stack.removeLast()
            stack[stack.count - 1].items.append(.group(unclosed))
        }
        return stack[0]
    }

    /// - Parameter character: A UTF-16 unit of the predicate.
    /// - Returns: Is it whitespace?
    private static func isWhitespace(_ character: unichar) -> Bool {
        Unicode.Scalar(character).map(CharacterSet.whitespacesAndNewlines.contains) ?? false
    }
}
