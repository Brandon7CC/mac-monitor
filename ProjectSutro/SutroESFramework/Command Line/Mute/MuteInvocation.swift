//
//  MuteInvocation.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Mute invocations
/// `macmonitor mute list|add|remove|import|export|reset`: the saved mute set Mac Monitor and `macmonitor` share.
public enum MuteInvocation: Equatable {
    /// The mute commands, by what's typed, in the order help lists them. The parser switches over every case with
    /// no default, so a command added here doesn't build until it's parsed.
    public enum Name: String, CaseIterable, Sendable {
        case list, add, remove, `import`, export, reset
        
        /// Every name, as help and usage errors list them: "list, add, remove, import, export or reset".
        static var listed: String {
            let names = allCases.map(\.rawValue)
            return names.dropLast().joined(separator: ", ") + " or " + (names.last ?? "")
        }
    }
    
    /// Show the saved set: a table, or the mute file `export` writes (`--format json`).
    case list(format: MuteListFormat = .text)
    /// Mute a path, for every event or some.
    case add(MuteFile.Entry)
    /// Unmute a path, or some of its events.
    case remove(MuteFile.Entry)
    /// Replace the saved set with a file's mutes, or add them (`--merge`). `-` reads standard input. Asks first
    /// unless `confirmed` (`--yes`).
    case importFile(path: String, merge: Bool, confirmed: Bool = false)
    /// Write the saved set as a mute file to standard output.
    case export
    /// Restore Mac Monitor's default set. Asks first unless `confirmed` (`--yes`).
    case reset(confirmed: Bool = false)
}


/// How `macmonitor mute list` shows the saved set.
public enum MuteListFormat: String, CaseIterable, Sendable {
    /// A table, one mute a line (``MuteTable``).
    case text
    /// The mute file `macmonitor mute export` writes, for scripts.
    case json
}


// MARK: - Parsing
extension CommandLineParser {
    /// The mute path types, by the short names `--type` takes.
    static let muteTypes: [String: es_mute_path_type_t] = [
        "literal": ES_MUTE_PATH_TYPE_LITERAL, "prefix": ES_MUTE_PATH_TYPE_PREFIX,
        "target-literal": ES_MUTE_PATH_TYPE_TARGET_LITERAL, "target-prefix": ES_MUTE_PATH_TYPE_TARGET_PREFIX
    ]
    
    /// `mute <subcommand> ...`.
    ///
    /// - Parameter cursor: The arguments after `mute`.
    /// - Returns: The mute command asked for.
    /// - Throws: ``CommandLineUsageError``.
    static func mute(_ cursor: inout ArgumentCursor) throws -> MuteInvocation {
        guard case .positional(let subcommand)? = cursor.next() else {
            throw CommandLineUsageError("mute needs one of \(MuteInvocation.Name.listed).", command: "mute")
        }
        guard let name = MuteInvocation.Name(rawValue: subcommand) else {
            let names = MuteInvocation.Name.allCases.map(\.rawValue)
            let suggestion = CommandLineSuggestion.didYouMean(subcommand, among: names)
            throw CommandLineUsageError("Unknown mute command '\(subcommand)'.\(suggestion)", command: "mute")
        }
        /// Every command, and no default: a new one doesn't build until it's parsed here.
        switch name {
        case .list: return .list(format: try muteListFormat(&cursor))
        case .export:
            try cursor.expectEnd(of: "mute export", command: "mute")
            return .export
        case .reset:
            let given = try cursor.flags(of: "mute reset", among: CommandLineOption.mute(.reset), positional: nil,
                                         command: "mute")
            return .reset(confirmed: given.flags.contains("--yes"))
        case .add: return .add(try muteEntry(&cursor, subcommand: "add"))
        case .remove: return .remove(try muteEntry(&cursor, subcommand: "remove"))
        case .import: return try muteImport(&cursor)
        }
    }
    
    /// `PATH [--type literal|prefix|target-literal|target-prefix] [--event EVENT]...`.
    ///
    /// - Parameters:
    ///   - cursor: The arguments.
    ///   - subcommand: `add` or `remove`, for messages.
    /// - Returns: The entry: the path, its type (literal unless given: the narrowest), and its events (none for every
    ///   event).
    /// - Throws: ``CommandLineUsageError``: for no path or more than one, an unknown option, or an option without its
    ///   value (64). For a relative path, an unknown type, or an event that isn't a NOTIFY event (65, as the Security
    ///   Extension's refusal of a mute that can't be used is).
    static func muteEntry(_ cursor: inout ArgumentCursor, subcommand: String) throws -> MuteFile.Entry {
        var path: String?, type = ES_MUTE_PATH_TYPE_LITERAL, events: [String] = []
        while let argument = cursor.next() {
            switch argument {
            case .positional(let value) where path == nil:
                guard value.hasPrefix("/") else {
                    throw CommandLineUsageError.unusableMute("'\(value)' isn't an absolute path.")
                }
                path = value
            case .positional(let value):
                throw CommandLineUsageError("mute \(subcommand) takes one path, not also '\(value)'.", command: "mute")
            case .option("--type", let attached):
                let value = try cursor.value(of: "--type", attached: attached, command: "mute")
                guard let named = muteTypes[value] ?? muteTypes.values.first(where: {
                    getMuteCaseString(muteType: $0) == value
                }) else {
                    throw CommandLineUsageError.unusableMute("""
                        --type must be literal, prefix, target-literal or target-prefix, not '\(value)'.
                        """)
                }
                type = named
            case .option("--event", let attached):
                let value = try cursor.value(of: "--event", attached: attached, command: "mute")
                guard let event = CommandLineEvents.notifyEvent(named: value) else {
                    let names = CommandLineEvents.catalog().map(\.name)
                    let suggestion = CommandLineSuggestion.didYouMean(value, among: names)
                    throw CommandLineUsageError.unusableMute(
                        "'\(value)' isn't a NOTIFY event Mac Monitor knows.\(suggestion)")
                }
                events.append(eventTypeToString(from: event))
            case .option(let option, _):
                throw unknownOption(option, for: "mute \(subcommand)", among: CommandLineOption.mute(.add))
            }
        }
        guard let path else { throw CommandLineUsageError("mute \(subcommand) needs a path.", command: "mute") }
        return MuteFile.Entry(path: path, type: getMuteCaseString(muteType: type), events: events)
    }
    
    /// `list [--format text|json]`.
    ///
    /// - Parameter cursor: The arguments.
    /// - Returns: The format: text unless given.
    /// - Throws: ``CommandLineUsageError`` for a positional, an unknown format, or an unknown option.
    static func muteListFormat(_ cursor: inout ArgumentCursor) throws -> MuteListFormat {
        var format = MuteListFormat.text
        while let argument = cursor.next() {
            switch argument {
            case .option("--format", let attached):
                let value = try cursor.value(of: "--format", attached: attached, command: "mute")
                guard let named = MuteListFormat(rawValue: value) else {
                    throw CommandLineUsageError("--format must be text or json, not '\(value)'.", command: "mute")
                }
                format = named
            case .option(let option, _):
                throw unknownOption(option, for: "mute list", among: CommandLineOption.mute(.list))
            case .positional(let value):
                throw CommandLineUsageError("mute list takes no arguments, not '\(value)'.", command: "mute")
            }
        }
        return format
    }
    
    /// `import FILE|- [--merge] [--yes]`.
    ///
    /// - Parameter cursor: The arguments.
    /// - Returns: The import.
    /// - Throws: ``CommandLineUsageError`` for no file or more than one, a value given to `--merge` or `--yes`, or an
    ///   unknown option.
    static func muteImport(_ cursor: inout ArgumentCursor) throws -> MuteInvocation {
        let (path, flags) = try cursor.flags(of: "mute import", among: CommandLineOption.mute(.import),
                                             positional: "file", command: "mute")
        guard let path else {
            throw CommandLineUsageError("mute import needs a file, or - for standard input.", command: "mute")
        }
        return .importFile(path: path, merge: flags.contains("--merge"), confirmed: flags.contains("--yes"))
    }
}
