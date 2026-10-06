//
//  CommandLineInvocation.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Invocation
/// What a `macmonitor` command line asks for, once parsed (``CommandLineParser``).
///
/// One case for each ``CommandLineCommand/Name-swift.enum``. A command added later gets its case here too, and the
/// switches below and in `CommandLineTool.run` won't build until they say which command it is and what it does.
public enum CommandLineInvocation: Equatable {
    /// Show help: for one command, or for `macmonitor` itself.
    case help(command: String?)
    /// Show the version.
    case version
    /// List the events `macmonitor` can stream.
    case events
    /// Stream events.
    case stream(StreamInvocation)
    /// Read or change the saved mute set.
    case mute(MuteInvocation)
    /// Write the telemetry schema.
    case schema
    /// Check a trace against the telemetry schema.
    case validate(ValidateInvocation)
    
    /// Does it need root? Its command decides (``CommandLineCommand/Name-swift.enum/requiresRoot``).
    public var requiresRoot: Bool { id.requiresRoot }
    
    /// The command it came from.
    public var id: CommandLineCommand.Name {
        switch self {
        case .help: return .help
        case .version: return .version
        case .events: return .events
        case .stream: return .stream
        case .mute: return .mute
        case .schema: return .schema
        case .validate: return .validate
        }
    }
    
    /// The command's name, for messages.
    public var command: String { id.rawValue }
}


// MARK: - Stream
/// `macmonitor stream [EVENT...] [--format text|jsonl] [--no-mutes] [--include-self]`.
public struct StreamInvocation: Equatable {
    /// The events, each once, in the order named. None means Mac Monitor's defaults.
    public var events: [es_event_type_t] = []
    /// The output format, or `nil` to choose by whether standard output is a terminal.
    public var format: StreamOutputFormat?
    /// Apply the saved mute set? `--no-mutes` turns it off.
    public var appliesSavedMutes: Bool = true
    /// Show the pipeline's own events? `--include-self`.
    public var includeSelf: Bool = false
    
    /// The defaults: Mac Monitor's events, the format by terminal, the saved mutes, without the pipeline's events.
    public init() {}
    
    /// The request's options for the Security Extension.
    public var options: StreamOptions {
        StreamOptions(events: events.map { eventTypeToString(from: $0) }, appliesSavedMutes: appliesSavedMutes)
    }
    
    /// The format to write in.
    ///
    /// - Parameter isTerminal: Is standard output a terminal?
    /// - Returns: The format asked for, else text on a terminal and JSONL anywhere else.
    public func resolvedFormat(isTerminal: Bool) -> StreamOutputFormat {
        format ?? (isTerminal ? .text : .jsonl)
    }
}


// MARK: - Validate
/// `macmonitor validate [--eslogger] TRACE`.
public struct ValidateInvocation: Equatable {
    /// The trace, as typed. `-` is kept, for ``ValidateCommand`` to refuse: a trace is read from a file.
    public var path: String
    /// Which keys are checked: every key, or with `--eslogger` only eslogger's.
    public var mode: TelemetryValidator.Mode
    
    /// - Parameters:
    ///   - path: The trace, as typed.
    ///   - mode: Which keys are checked: every key unless given.
    public init(path: String, mode: TelemetryValidator.Mode = .macMonitor) {
        self.path = path
        self.mode = mode
    }
}


// MARK: - Usage errors
/// A command line `macmonitor` can't act on: exit 64 (`EX_USAGE`) for one it can't read, such as an unknown option or
/// a missing argument, or 65 (`EX_DATAERR`) for one that names a mute that can't be used, such as a relative path.
public struct CommandLineUsageError: Error, Equatable, CustomStringConvertible {
    /// What's wrong, as a sentence.
    public let message: String
    /// The command it's about, if any, for the hint to its help.
    public let command: String?
    /// Where to read more instead of the command's help, such as "Run 'macmonitor events' to list them."
    public let hint: String?
    /// How `macmonitor` exits: ``CommandLineExit/usage``, or ``CommandLineExit/dataError`` for a mute that can't be
    /// used.
    public let exit: CommandLineExit
    
    /// - Parameters:
    ///   - message: What's wrong.
    ///   - command: The command it's about.
    ///   - hint: Where to read more, if not the command's help.
    ///   - exit: How `macmonitor` exits: 64 unless given.
    public init(_ message: String, command: String? = nil, hint: String? = nil, exit: CommandLineExit = .usage) {
        self.message = message
        self.command = command
        self.hint = hint
        self.exit = exit
    }
    
    /// A mute on the command line that can't be used, such as one with a relative path or an unknown event. It exits
    /// 65, as a mute the Security Extension refuses does.
    ///
    /// - Parameter message: What's wrong with it.
    /// - Returns: The error, pointing to `mute`'s help.
    static func unusableMute(_ message: String) -> CommandLineUsageError {
        CommandLineUsageError(message, command: "mute", exit: .dataError)
    }
    
    /// The message and where to read more, such as "Run 'macmonitor help stream'."
    public var description: String {
        "\(message) \(hint ?? "Run 'macmonitor help\(command.map { " \($0)" } ?? "")'.")"
    }
}
