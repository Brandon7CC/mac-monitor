//
//  ReadOnlyTextView+Syntax.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import AppKit


// MARK: - Finding the language
extension ReadOnlyTextView.Language {
    /// The language of a file Mac Monitor read. Its extension decides, then its `#!` line, then the program that ran
    /// it.
    ///
    /// - Parameters:
    ///   - path: The file's path.
    ///   - content: Its text.
    ///   - interpreter: The program that ran it, such as `/bin/zsh`, if one did.
    /// - Returns: The language, or `.plain` when none fits.
    static func of(path: String, content: String, interpreter: String? = nil) -> Self {
        let byExtension: [String: Self] = [
            "sh": .shell, "bash": .shell, "zsh": .shell, "ksh": .shell, "command": .shell,
            "py": .python, "js": .javascript, "jxa": .javascript, "mjs": .javascript,
            "applescript": .applescript, "rb": .ruby, "pl": .perl, "pm": .perl,
            "plist": .xml, "xml": .xml, "json": .json
        ]
        let isXML = content.drop(while: \.isWhitespace).hasPrefix("<")
        let language = byExtension[(path as NSString).pathExtension.lowercased()] ?? shebang(of: content)
            ?? interpreter.flatMap(named) ?? (isXML ? .xml : .plain)
        /// A property list that isn't XML, such as one Mac Monitor wrote out from binary, stays plain.
        return language == .xml && !isXML ? .plain : language
    }

    /// - Parameter content: A script's text.
    /// - Returns: The language its `#!` line names, such as `#!/usr/bin/env python3`.
    private static func shebang(of content: String) -> Self? {
        guard content.hasPrefix("#!") else { return nil }
        let words = content.dropFirst(2).prefix { $0 != "\n" }.split(separator: " ").map(String.init)
        guard let first = words.first?.lastPathComponent else { return nil }
        if first == "osascript", words.contains("JavaScript") { return .javascript }
        /// `env` runs the first word after it that isn't an option or a variable.
        let program = first == "env" ? words.dropFirst().first { !$0.hasPrefix("-") && !$0.contains("=") } : first
        return program.flatMap(named)
    }

    /// - Parameter program: A program's name, such as `zsh` or `python3.11`.
    /// - Returns: The language it runs.
    private static func named(_ program: String) -> Self? {
        let name = program.lastPathComponent
        if ["sh", "bash", "zsh", "ksh", "dash", "csh", "tcsh"].contains(name) { return .shell }
        if name == "osascript" { return .applescript }
        if name == "node" { return .javascript }
        let families: [(prefix: String, language: Self)] = [("python", .python), ("perl", .perl), ("ruby", .ruby)]
        return families.first { name.hasPrefix($0.prefix) }?.language
    }
}


// MARK: - Coloring
extension ReadOnlyTextView.Language {
    /// What a token is, for its color.
    private enum Style {
        case comment, string, key, keyword, number, variable

        /// Its attributes, as Xcode colors code (``PredicateSyntax``'s colors).
        var attributes: [NSAttributedString.Key: Any] {
            switch self {
            case .comment: [.foregroundColor: PredicateSyntax.commentColor]
            case .string: [.foregroundColor: PredicateSyntax.stringColor]
            case .key: [.foregroundColor: PredicateSyntax.keyColor]
            case .keyword: [.foregroundColor: PredicateSyntax.keywordColor, .font: PredicateSyntax.boldFont]
            case .number: [.foregroundColor: PredicateSyntax.numberColor]
            case .variable: [.foregroundColor: PredicateSyntax.variableColor]
            }
        }
    }

    /// Text past this many UTF-16 units stays plain, so a huge file opens at once.
    private static let colorLimit = 1_000_000

    /// Color text in this language. The text's font and plain color are already set.
    ///
    /// - Parameter storage: The text.
    func color(_ storage: NSTextStorage) {
        guard let (pattern, styles) = Self.patterns[self], storage.length <= Self.colorLimit else { return }
        for match in pattern.matches(in: storage.string, range: NSRange(location: 0, length: storage.length)) {
            /// One group per rule. The first that matched is the token's.
            guard let rule = (1...styles.count).first(where: { match.range(at: $0).location != NSNotFound })
            else { continue }
            storage.addAttributes(styles[rule - 1].attributes, range: match.range)
        }
    }

    /// Each language's rules joined into one pattern, earliest rule first, with each rule's style.
    ///
    /// The pattern finds tokens left to right, so a `#` inside a string stays part of the string.
    private static let patterns: [Self: (NSRegularExpression, [Style])] = rules.mapValues { rules in
        let joined = rules.map { "(\($0.1))" }.joined(separator: "|")
        return (try! NSRegularExpression(pattern: joined), rules.map(\.0))
    }

    /// A language's tokens, as (style, pattern without capture groups), in the order they're tried.
    private static let rules: [Self: [(Style, String)]] = {
        let double = #""(?:[^"\\]|\\.)*""#, single = #"'(?:[^'\\\n]|\\.)*'"#
        let number = #"\b(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?)\b"#
        /// - Parameter words: Keywords.
        /// - Returns: A pattern for any of them as a whole word.
        func keywords(_ words: String) -> String {
            #"\b(?:"# + words.split(separator: " ").joined(separator: "|") + #")\b"#
        }
        return [
            .json: [(.key, double + #"(?=\s*:)"#), (.string, double), (.keyword, keywords("true false null")),
                    (.number, #"-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b"#)],
            .shell: [(.comment, #"(?<![\w$\{])#.*"#), (.string, double), (.string, "'[^']*'"),
                     (.variable, #"\$\{[^}]*\}|\$\w+|\$[@*#?$!0-9-]"#),
                     (.keyword, keywords("if then else elif fi for while until do done case esac in function "
                                         + "return exit local export readonly declare typeset unset source eval "
                                         + "exec trap shift break continue")), (.number, number)],
            .python: [(.comment, "#.*"), (.string, #"[rRbBuUfF]{0,2}(?:"""[\s\S]*?"""|'''[\s\S]*?''')"#),
                      (.string, #"[rRbBuUfF]{0,2}(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')"#),
                      (.keyword, keywords("False None True and as assert async await break class continue def "
                                          + "del elif else except finally for from global if import in is lambda "
                                          + "nonlocal not or pass raise return try while with yield")),
                      (.variable, #"@\w+"#), (.number, number)],
            .javascript: [(.comment, #"//.*|/\*[\s\S]*?\*/"#), (.string, #""(?:[^"\\\n]|\\.)*""#), (.string, single),
                          (.string, #"`(?:[^`\\]|\\.)*`"#),
                          (.keyword, keywords("var let const function return if else for while do switch case "
                                              + "default break continue new delete typeof instanceof in of try "
                                              + "catch finally throw class extends super this null undefined true "
                                              + "false import export from async await yield")), (.number, number)],
            .applescript: [(.comment, #"--.*|#.*|\(\*[\s\S]*?\*\)"#), (.string, double),
                           (.keyword, "(?i)" + keywords("tell end on to set get copy return if then else repeat "
                                                        + "while until with without times from by error try "
                                                        + "considering ignoring script property global local my "
                                                        + "of in it me do shell display dialog run activate "
                                                        + "application quit and or not is contains true false")),
                           (.number, number)],
            .ruby: [(.comment, "#.*"), (.string, double), (.string, single), (.variable, #"[@$]{1,2}\w+"#),
                    (.keyword, keywords("def end class module if elsif else unless while until for in do return "
                                        + "yield begin rescue ensure raise then case when require require_relative "
                                        + "nil true false self and or not")), (.number, number)],
            .perl: [(.comment, #"(?<![$\w])#.*"#), (.string, double), (.string, single),
                    (.variable, #"\$\{[^}]*\}|[$@%][\w:]+"#),
                    (.keyword, keywords("my our local sub if elsif else unless while until for foreach do return "
                                        + "use require package last next redo die print open close eval undef "
                                        + "defined exists delete and or not")), (.number, number)],
            .xml: [(.comment, #"<!--[\s\S]*?-->"#), (.key, #"<[?!/]?[\w:.-]+|\??/?>"#), (.string, #""[^"]*""#),
                   (.variable, #"\b[\w:-]+(?==)"#)]
        ]
    }()
}
