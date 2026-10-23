//
//  PredicateText.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/23/26.
//

import Foundation


// MARK: - Predicate text
/// A predicate's text, read without parsing it: its tokens, which the predicate editor colors, its boolean key paths
/// that stand alone, which `NSPredicate` can't read, and what completes the word being typed.
public enum PredicateText {
    /// One token of a predicate.
    public struct Token: Equatable {
        public enum Kind { case string, keyword, comparison, number, keyPath, variable, function }
        public let kind: Kind
        public let text: String
        public let range: NSRange
    }

    private static let expression = try! NSRegularExpression(pattern: [
        #""(?:[^"\\]|\\.)*"?|'(?:[^'\\]|\\.)*'?"#,
        #"\b(?:AND|OR|NOT|ANY|ALL|NONE|IN|CONTAINS|BEGINSWITH|ENDSWITH|MATCHES|LIKE|BETWEEN|TRUEPREDICATE"#
            + #"|FALSEPREDICATE|TRUE|FALSE|NIL|NULL|YES|NO)\b(?:\[[cd]+\])?"#,
        #"==|!=|>=|<=|=|<|>"#,
        #"\b\d+(?:\.\d+)?\b"#,
        #"\$[A-Za-z_]\w*(?:\.[\w@]+)*"#,
        #"[A-Za-z_@][\w@]*(?:\.[\w@]+)*"#,
    ].joined(separator: "|"), options: [.caseInsensitive])

    private static let keywords: Set<String> = [
        "AND", "OR", "NOT", "ANY", "ALL", "NONE", "IN", "CONTAINS", "BEGINSWITH", "ENDSWITH", "MATCHES", "LIKE",
        "BETWEEN", "TRUEPREDICATE", "FALSEPREDICATE", "TRUE", "FALSE", "NIL", "NULL", "YES", "NO",
    ]

    /// - Parameter text: A predicate.
    /// - Returns: Its tokens, in order.
    public static func tokens(in text: String) -> [Token] {
        let string = text as NSString
        return expression.matches(in: text, range: NSRange(location: 0, length: string.length)).map { match in
            let token = string.substring(with: match.range)
            let first = token.first ?? " "
            let kind: Token.Kind
            if first == "\"" || first == "'" {
                kind = .string
            } else if "=!<>".contains(first) {
                kind = .comparison
            } else if first.isNumber {
                kind = .number
            } else if first == "$" {
                kind = .variable
            } else if NSMaxRange(match.range) < string.length,
                      string.substring(with: NSRange(location: NSMaxRange(match.range), length: 1)) == "(" {
                kind = .function
            } else if token.range(of: #"^[A-Za-z]+(\[[cd]+\])?$"#, options: .regularExpression) != nil,
                      keywords.contains(token.uppercased().replacingOccurrences(of: #"\[[CD]+\]"#, with: "",
                                                                                   options: .regularExpression)) {
                kind = .keyword
            } else {
                kind = .keyPath
            }
            return Token(kind: kind, text: token, range: match.range)
        }
    }

    /// A key path token's keys from the record: a variable's (`$e.`) without the variable.
    ///
    /// - Parameter token: A key path or variable token.
    /// - Returns: Its keys.
    public static func keys(of token: Token) -> [String] {
        let keys = token.text.components(separatedBy: ".")
        return token.kind == .variable ? Array(keys.dropFirst()) : keys
    }

    // MARK: Booleans alone
    /// The predicate with each boolean key path that stands alone compared to `YES`:
    /// `event.exec.target.is_adhoc_signed AND …` reads `event.exec.target.is_adhoc_signed == YES AND …`, which
    /// `NSPredicate` can parse. One stands alone between the start, `(`, `,`, `AND`, `OR` or `NOT` and the end, `)`,
    /// `,`, `AND` or `OR`.
    ///
    /// - Parameter text: A predicate.
    /// - Returns: The predicate, compared where it needs to be.
    public static func comparingBooleans(_ text: String) -> String {
        let string = text as NSString
        let tokens = tokens(in: text)
        var insertions: [Int] = []
        for (index, token) in tokens.enumerated() where [.keyPath, .variable].contains(token.kind) {
            guard RecordKeyPaths.shared.nodes[keys(of: token).joined(separator: ".")]?.type == "boolean" else {
                continue
            }
            let previous = index > 0 ? tokens[index - 1] : nil
            let next = index + 1 < tokens.count ? tokens[index + 1] : nil
            let beforeStart = previous.map { NSMaxRange($0.range) } ?? 0
            let before = string.substring(with: NSRange(location: beforeStart,
                                                        length: token.range.location - beforeStart))
            let afterEnd = next?.range.location ?? string.length
            let after = string.substring(with: NSRange(location: NSMaxRange(token.range),
                                                       length: afterEnd - NSMaxRange(token.range)))
            let opens = previous.map { isJoiner($0, ["AND", "OR", "NOT"]) } ?? true
                || ["(", ",", "&&", "||", "!"].contains(where: before.contains)
            let closes = next.map { isJoiner($0, ["AND", "OR"]) } ?? true
                || [")", ",", "&&", "||"].contains(where: after.contains)
            if opens, closes { insertions.append(NSMaxRange(token.range)) }
        }
        let result = NSMutableString(string: text)
        for location in insertions.reversed() { result.insert(" == YES", at: location) }
        return result as String
    }

    /// - Parameters:
    ///   - token: A token.
    ///   - words: Keywords.
    /// - Returns: Is it one of them?
    private static func isJoiner(_ token: Token, _ words: [String]) -> Bool {
        token.kind == .keyword && words.contains(token.text.uppercased())
    }

    // MARK: Completion
    /// What completes the word being typed.
    public struct Completion: Equatable {
        /// The word, which each completion replaces.
        public let range: NSRange
        /// The completions, in order.
        public let words: [String]
    }

    /// The keywords completed, besides key paths and related events.
    private static let completedKeywords = [
        "AND", "OR", "NOT", "ANY", "ALL", "NONE", "IN", "CONTAINS", "CONTAINS[c]", "BEGINSWITH", "ENDSWITH", "MATCHES",
        "LIKE", "BETWEEN", "SUBQUERY", "YES", "NO", "TRUEPREDICATE", "FALSEPREDICATE",
    ]
    /// The most key paths completed by their last key alone, `is_adhoc` for `event.exec.target.is_adhoc_signed`.
    private static let byLastKeyLimit = 40

    /// What completes the word before a location: a key path's next key (`event.exec.ta` → `event.exec.target`), a
    /// keyword or related events, a key path by its last key (`is_adhoc`), or inside quotes a value the schema
    /// lists, such as an event type's name.
    ///
    /// - Parameters:
    ///   - text: A predicate.
    ///   - location: Where the word ends, the cursor.
    /// - Returns: The word and its completions, or `nil` if there's no word or nothing completes it.
    public static func completions(in text: String, at location: Int) -> Completion? {
        let string = text as NSString
        guard location <= string.length else { return nil }
        if let quoted = tokens(in: text).first(where: { isInside($0, location) }) {
            let range = NSRange(location: quoted.range.location + 1, length: location - quoted.range.location - 1)
            let fragment = string.substring(with: range).lowercased()
            let values = Set(RecordKeyPaths.shared.nodes.values.flatMap(\.values))
                .filter { $0.lowercased().hasPrefix(fragment) && $0.lowercased() != fragment }.sorted()
            return values.isEmpty ? nil : Completion(range: range, words: values)
        }
        var start = location
        let word = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "_@.$"))
        while start > 0, let scalar = Unicode.Scalar(string.character(at: start - 1)), word.contains(scalar) {
            start -= 1
        }
        let range = NSRange(location: start, length: location - start)
        let typed = string.substring(with: range)
        guard !typed.isEmpty else { return nil }
        var words: [String]
        if typed.hasPrefix("$") {
            guard let dot = typed.firstIndex(of: ".") else { return nil }
            let variable = String(typed[...dot])
            words = pathCompletions(String(typed[typed.index(after: dot)...]), keywords: false).map { variable + $0 }
        } else {
            words = pathCompletions(typed, keywords: true)
        }
        words.removeAll { $0 == typed }
        return words.isEmpty ? nil : Completion(range: range, words: words)
    }

    /// - Parameters:
    ///   - token: A token.
    ///   - location: The cursor.
    /// - Returns: Is the cursor inside a string token, after its quote and before any closing one?
    private static func isInside(_ token: Token, _ location: Int) -> Bool {
        guard token.kind == .string, location > token.range.location else { return false }
        let closed = token.text.count > 1 && token.text.last == token.text.first
        return location < NSMaxRange(token.range) || (location == NSMaxRange(token.range) && !closed)
    }

    /// - Parameters:
    ///   - typed: A key path being typed, without a variable.
    ///   - keywords: Complete keywords and related events too?
    /// - Returns: Its completions.
    private static func pathCompletions(_ typed: String, keywords: Bool) -> [String] {
        let keyPaths = RecordKeyPaths.shared
        let lowered = typed.lowercased()
        if let dot = typed.lastIndex(of: ".") {
            let parent = String(typed[..<dot]), fragment = typed[typed.index(after: dot)...].lowercased()
            guard let node = keyPaths.nodes[parent] else { return [] }
            return node.children.filter { $0.lowercased().hasPrefix(fragment) }.map { parent + "." + $0 }
        }
        var words = (keyPaths.nodes[""]?.children ?? []).filter { $0.lowercased().hasPrefix(lowered) }
        if keywords {
            words += (completedKeywords + PredicateRelation.allCases.map(\.rawValue))
                .filter { $0.lowercased().hasPrefix(lowered) }
        }
        if typed.count >= 3 {
            words += keyPaths.paths.lazy.filter { path in
                path.contains(".") && (path.split(separator: ".").last ?? "").lowercased().hasPrefix(lowered)
            }.prefix(byLastKeyLimit)
        }
        return words
    }
}
