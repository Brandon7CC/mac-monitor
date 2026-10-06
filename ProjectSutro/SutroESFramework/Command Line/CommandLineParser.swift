//
//  CommandLineParser.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Arguments
/// Walks a command's arguments: options (`--name`, `--name=value`, `-h`) and positionals in any order, with `--`
/// ending the options. A lone `-` is a positional (standard input).
struct ArgumentCursor {
    /// One argument.
    enum Argument: Equatable {
        /// An option with its dashes, and its value if it was attached with `=`.
        case option(String, value: String?)
        /// Anything else.
        case positional(String)
        
        /// What was typed: the option without its attached value, or the positional.
        var text: String {
            switch self {
            case .option(let option, _): return option
            case .positional(let positional): return positional
            }
        }
    }
    
    private var remaining: ArraySlice<String>
    private var optionsEnded = false
    
    /// - Parameter arguments: The command's arguments, after its name.
    init(_ arguments: ArraySlice<String>) {
        remaining = arguments
    }
    
    /// The next argument.
    ///
    /// - Returns: The argument, or `nil` at the end.
    mutating func next() -> Argument? {
        guard let argument = remaining.popFirst() else { return nil }
        guard !optionsEnded, argument.hasPrefix("-"), argument != "-" else { return .positional(argument) }
        if argument == "--" {
            optionsEnded = true
            return next()
        }
        guard argument.hasPrefix("--"), let equals = argument.firstIndex(of: "=") else {
            return .option(argument, value: nil)
        }
        return .option(String(argument[..<equals]), value: String(argument[argument.index(after: equals)...]))
    }
    
    /// An option's value: the one attached with `=`, else the next argument.
    ///
    /// - Parameters:
    ///   - option: The option, such as `--format`.
    ///   - attached: The value attached with `=`, if any.
    ///   - command: The command, for the error.
    /// - Returns: The value.
    /// - Throws: ``CommandLineUsageError`` if there's no value.
    mutating func value(of option: String, attached: String?, command: String) throws -> String {
        if let attached { return attached }
        guard let value = remaining.first, !value.hasPrefix("-") || value == "-" else {
            throw CommandLineUsageError("\(option) needs a value.", command: command)
        }
        remaining.removeFirst()
        return value
    }
    
    /// Refuse any argument left.
    ///
    /// - Parameters:
    ///   - name: What takes no arguments, such as "events" or "mute export", for the message.
    ///   - command: The command whose help the error points to.
    /// - Throws: ``CommandLineUsageError`` if there's an argument left.
    mutating func expectEnd(of name: String, command: String) throws {
        guard let argument = next() else { return }
        throw CommandLineUsageError("\(name) takes no arguments, not '\(argument.text)'.", command: command)
    }
}


// MARK: - Parser
/// Reads `macmonitor`'s command line. Hand-rolled, with no dependencies: a handful of commands and options.
public enum CommandLineParser {
    /// Read a command line.
    ///
    /// `-h` or `--help` anywhere before `--` asks for the command's help instead. No arguments ask for `macmonitor`'s.
    ///
    /// - Parameter arguments: The arguments, without the program's name.
    /// - Returns: What they ask for.
    /// - Throws: ``CommandLineUsageError``.
    public static func parse(_ arguments: [String]) throws -> CommandLineInvocation {
        guard let name = arguments.first else { return .help(command: nil) }
        if name == "--version" { return .version }
        if isHelp(name) { return .help(command: nil) }
        guard let command = CommandLineHelp.command(named: name) else {
            let kind = name.hasPrefix("-") ? "option" : "command"
            throw CommandLineUsageError("Unknown \(kind) '\(name)'.")
        }
        let rest = arguments.dropFirst()
        if rest.prefix(while: { $0 != "--" }).contains(where: isHelp), command.id != .help {
            return .help(command: command.name)
        }
        var cursor = ArgumentCursor(rest)
        /// Every command, and no default: a new one doesn't build until it's parsed here.
        switch command.id {
        case .stream: return .stream(try stream(&cursor))
        case .mute: return .mute(try mute(&cursor))
        case .validate: return .validate(try validate(&cursor))
        case .help: return .help(command: try help(&cursor))
        case .events: return try takingNothing(&cursor, .events)
        case .schema: return try takingNothing(&cursor, .schema)
        case .version: return try takingNothing(&cursor, .version)
        }
    }
    
    /// Is an argument a request for help?
    ///
    /// - Parameter argument: The argument.
    /// - Returns: `true` for `-h` and `--help`.
    static func isHelp(_ argument: String) -> Bool {
        argument == "-h" || argument == "--help"
    }
    
    /// `stream [EVENT...] [--format text|jsonl] [--no-mutes] [--include-self]`.
    ///
    /// - Parameter cursor: The arguments.
    /// - Returns: The stream asked for.
    /// - Throws: ``CommandLineUsageError`` for an event that can't be streamed, a bad format, or an unknown option.
    static func stream(_ cursor: inout ArgumentCursor) throws -> StreamInvocation {
        var invocation = StreamInvocation(), seen = Set<UInt32>()
        while let argument = cursor.next() {
            switch argument {
            case .positional(let name):
                let events = name == "all" ? supportedEvents : [try event(named: name)]
                invocation.events += events.filter { seen.insert($0.rawValue).inserted }
            case .option("--format", let attached):
                let value = try cursor.value(of: "--format", attached: attached, command: "stream")
                guard let format = StreamOutputFormat(rawValue: value) else {
                    throw CommandLineUsageError("--format must be text or jsonl, not '\(value)'.", command: "stream")
                }
                invocation.format = format
            case .option("--no-mutes", nil):
                invocation.appliesSavedMutes = false
            case .option("--include-self", nil):
                invocation.includeSelf = true
            case .option(let option, .some) where option == "--no-mutes" || option == "--include-self":
                throw CommandLineUsageError("\(option) takes no value.", command: "stream")
            case .option(let option, _):
                throw CommandLineUsageError("Unknown option '\(option)' for stream.", command: "stream")
            }
        }
        return invocation
    }
    
    /// The event a name on the command line stands for.
    ///
    /// - Parameter name: A short or full event name.
    /// - Returns: The event.
    /// - Throws: ``CommandLineUsageError`` for an AUTH event, one Mac Monitor doesn't model, or a name that isn't one.
    static func event(named name: String) throws -> es_event_type_t {
        guard let event = CommandLineEvents.event(named: name) else {
            throw CommandLineUsageError("'\(name)' isn't an event macmonitor can stream.",
                                        hint: "Run 'macmonitor events' to list them.")
        }
        return event
    }
    
    /// `validate [--eslogger] TRACE`. An argument a message repeats is escaped for a terminal: `validate *.jsonl`
    /// expands to file names anyone can choose.
    ///
    /// - Parameter cursor: The arguments.
    /// - Returns: The trace to check, and how.
    /// - Throws: ``CommandLineUsageError`` for no trace or more than one, a value given to `--eslogger`, or an unknown
    ///   option.
    static func validate(_ cursor: inout ArgumentCursor) throws -> ValidateInvocation {
        var path: String?, mode = TelemetryValidator.Mode.macMonitor
        while let argument = cursor.next() {
            switch argument {
            case .positional(let value) where path == nil:
                path = value
            case .positional(let value):
                throw CommandLineUsageError("validate takes one trace, not also '\(TerminalSafeText.text(value))'.",
                                            command: "validate")
            case .option("--eslogger", nil):
                mode = .eslogger
            case .option("--eslogger", .some):
                throw CommandLineUsageError("--eslogger takes no value.", command: "validate")
            case .option(let option, _):
                throw CommandLineUsageError("Unknown option '\(TerminalSafeText.text(option))' for validate.",
                                            command: "validate")
            }
        }
        guard let path else { throw CommandLineUsageError("validate needs a trace.", command: "validate") }
        return ValidateInvocation(path: path, mode: mode)
    }
    
    /// `help [COMMAND]`. `-h` or `--help` asks for help's own help, as it does for every other command.
    ///
    /// - Parameter cursor: The arguments.
    /// - Returns: The command to show help for, or `nil` for `macmonitor`'s.
    /// - Throws: ``CommandLineUsageError`` for an unknown command, or more than one.
    static func help(_ cursor: inout ArgumentCursor) throws -> String? {
        var topic: String?
        while let argument = cursor.next() {
            if case .option(let option, _) = argument, isHelp(option) { return "help" }
            guard case .positional(let name) = argument, topic == nil else {
                throw CommandLineUsageError("help takes one command at most.", command: "help")
            }
            guard CommandLineHelp.command(named: name) != nil else {
                throw CommandLineUsageError("Unknown command '\(name)'.")
            }
            topic = name
        }
        return topic
    }
    
    /// A command that takes no arguments.
    ///
    /// - Parameters:
    ///   - cursor: The arguments.
    ///   - invocation: What the command asks for.
    /// - Returns: `invocation`.
    /// - Throws: ``CommandLineUsageError`` if there's any argument.
    static func takingNothing(_ cursor: inout ArgumentCursor,
                              _ invocation: CommandLineInvocation) throws -> CommandLineInvocation {
        try cursor.expectEnd(of: invocation.command, command: invocation.command)
        return invocation
    }
}
