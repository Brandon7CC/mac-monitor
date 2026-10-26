//
//  CommandLineOptions.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/22/26.
//

import Foundation


// MARK: - Options
/// An option a `macmonitor` command takes, for suggesting the one meant when another is mistyped and for shell
/// completion. The parsers read the options themselves: the tests check every option listed here parses.
public struct CommandLineOption: Equatable {
    /// What an option takes, or what a command takes besides its options.
    public enum Value: Equatable {
        /// Nothing.
        case none
        /// One of these words.
        case choice([String])
        /// A file or a path.
        case file
        /// An event's name.
        case event
        /// Anything else, such as a regular expression or a time.
        case text
    }

    /// The option, with its dashes.
    public let name: String
    /// What it takes.
    public let value: Value

    /// - Parameters:
    ///   - name: The option, with its dashes.
    ///   - value: What it takes: nothing unless given.
    public init(_ name: String, _ value: Value = .none) {
        self.name = name
        self.value = value
    }

    /// `stream`'s options.
    static let stream: [CommandLineOption] = [
        CommandLineOption("--format", .choice(StreamOutputFormat.allCases.map(\.rawValue))),
        CommandLineOption("--json"), CommandLineOption("--pretty"), CommandLineOption("--text"),
        CommandLineOption("--no-mutes"), CommandLineOption("--include-self"),
        CommandLineOption("--for", .text), CommandLineOption("--count", .text), CommandLineOption("--pid", .text)
    ] + ["--process", "--signing-id", "--target", "--grep", "--predicate"].map { CommandLineOption($0, .text) }

    /// `validate`'s options.
    static let validate = [CommandLineOption("--eslogger")]

    /// A mute command's options.
    ///
    /// - Parameter command: The mute command.
    /// - Returns: Its options.
    static func mute(_ command: MuteInvocation.Name) -> [CommandLineOption] {
        switch command {
        case .list: return [CommandLineOption("--format", .choice(MuteListFormat.allCases.map(\.rawValue)))]
        case .add, .remove:
            return [CommandLineOption("--type", .choice(CommandLineParser.muteTypes.keys.sorted())),
                    CommandLineOption("--event", .event)]
        case .import: return [CommandLineOption("--merge"), CommandLineOption("--yes")]
        case .export: return []
        case .reset: return [CommandLineOption("--yes")]
        }
    }
}


// MARK: - Suggestions
/// "Did you mean …?" for a mistyped command, option or event.
public enum CommandLineSuggestion {
    /// A sentence suggesting the name meant, to follow a usage error's first sentence.
    ///
    /// - Parameters:
    ///   - typed: What was typed.
    ///   - names: What could have been meant.
    /// - Returns: Such as " Did you mean 'stream'?", or "" when nothing is close enough.
    static func didYouMean(_ typed: String, among names: [String]) -> String {
        closest(to: typed, among: names).map { " Did you mean '\($0)'?" } ?? ""
    }

    /// The name closest to what was typed, ignoring case, if it's close enough to be a typo: at most one edit for up
    /// to five characters, two for up to eight, and three after that.
    ///
    /// - Parameters:
    ///   - typed: What was typed.
    ///   - names: What could have been meant.
    /// - Returns: The closest name, the first listed on a tie, or `nil`.
    static func closest(to typed: String, among names: [String]) -> String? {
        let limit = max(1, min(3, typed.count / 3))
        let typed = Array(typed.lowercased())
        return names.map { ($0, distance(typed, Array($0.lowercased()))) }
            .filter { $0.1 <= limit }
            .min { $0.1 < $1.1 }?.0
    }

    /// The edits between two strings: inserting, deleting or changing a character, or swapping two next to each
    /// other, each counts one (the optimal string alignment distance).
    ///
    /// - Parameters:
    ///   - a: One string's characters.
    ///   - b: The other's.
    /// - Returns: The number of edits.
    static func distance(_ a: [Character], _ b: [Character]) -> Int {
        guard !a.isEmpty, !b.isEmpty else { return max(a.count, b.count) }
        /// `rows[i][j]`: the edits between the first `i` characters of `a` and the first `j` of `b`.
        var rows = (0...a.count).map { i in (0...b.count).map { j in i == 0 ? j : (j == 0 ? i : 0) } }
        for i in 1...a.count {
            for j in 1...b.count {
                let change = a[i - 1] == b[j - 1] ? 0 : 1
                rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + change)
                if i > 1, j > 1, a[i - 1] == b[j - 2], a[i - 2] == b[j - 1] {
                    rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
                }
            }
        }
        return rows[a.count][b.count]
    }
}


// MARK: - Unknown options
extension CommandLineParser {
    /// The usage error for an option a command doesn't take, suggesting the one meant.
    ///
    /// - Parameters:
    ///   - option: The option.
    ///   - name: The command, such as "stream" or "mute add".
    ///   - options: The options it takes.
    /// - Returns: Such as "Unknown option '--fromat' for stream. Did you mean '--format'?"
    static func unknownOption(_ option: String, for name: String,
                              among options: [CommandLineOption]) -> CommandLineUsageError {
        let suggestion = CommandLineSuggestion.didYouMean(option, among: options.map(\.name))
        return CommandLineUsageError("Unknown option '\(TerminalSafeText.text(option))' for \(name).\(suggestion)",
                                     command: String(name.prefix { $0 != " " }))
    }
}
