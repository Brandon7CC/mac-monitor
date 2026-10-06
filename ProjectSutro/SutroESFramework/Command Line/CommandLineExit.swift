//
//  CommandLineExit.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Exit statuses
/// `macmonitor`'s exit statuses, from `sysexits.h`. A stream or a check stopped by a signal exits by that signal
/// instead (130 for Ctrl-C), and a closed pipe (`| head`) is a success, except that `validate` keeps its verdict: 65
/// for a trace that doesn't follow the schema, piped or not.
public enum CommandLineExit: Int32, Sendable {
    /// Done, or, for every command but `validate`, the reader closed the pipe. For `validate`, the trace has records
    /// and every one follows the schema.
    case success = 0
    /// The answer to "Continue?" was no, so nothing changed.
    case declined = 1
    /// A command line `macmonitor` can't act on: an unknown command or option, a missing argument, or a change that
    /// asks first with no terminal to ask at (`EX_USAGE`).
    case usage = 64
    /// Data `macmonitor` can't use: mutes named on the command line (a relative path, an unknown type or event), in a
    /// file to import, or refused by the Security Extension; or a trace to validate with a record that doesn't follow
    /// the telemetry schema or isn't JSON, or with no records (`EX_DATAERR`).
    case dataError = 65
    /// A file to import, or a trace to validate, that can't be read: missing, unreadable, or not a regular file
    /// (`EX_NOINPUT`).
    case noInput = 66
    /// The Security Extension isn't running, refused `macmonitor`, is out of date, or lacks Full Disk Access
    /// (`EX_UNAVAILABLE`).
    case unavailable = 69
    /// A bug (`EX_SOFTWARE`).
    case software = 70
    /// Standard output, or the saved mute set, can't be written (`EX_IOERR`).
    case ioError = 74
    /// Too many streams, or Endpoint Security clients: try again later (`EX_TEMPFAIL`).
    case temporaryFailure = 75
    /// Not root (`EX_NOPERM`).
    case noPermission = 77
}


// MARK: - Failures
/// Why `macmonitor` stops, with what to tell the user and how to exit.
public struct CommandLineFailure: Error, Equatable, CustomStringConvertible {
    /// The exit status.
    public let exit: CommandLineExit
    /// What to tell the user, as a sentence or two.
    public let message: String
    
    /// The NSXPC error codes `macmonitor` can tell apart (`NSCocoaErrorDomain`).
    enum XPCError: Int {
        /// The connection was interrupted: refused before any reply, or the Security Extension exited after.
        case interrupted = 4097
        /// The connection is invalid: no such service, or it went away.
        case invalid = 4099
        /// The Security Extension didn't satisfy `macmonitor`'s code signing requirement.
        case codeSigningRequirementFailed = 4102
    }
    
    /// - Parameters:
    ///   - exit: The exit status.
    ///   - message: What to tell the user.
    public init(_ exit: CommandLineExit, _ message: String) {
        self.exit = exit
        self.message = message
    }
    
    /// The message, as `macmonitor` prints it on standard error.
    public var description: String {
        "macmonitor: \(message)"
    }
    
    /// A command that needs root, run without it: says how to run the same command line again with `sudo`.
    ///
    /// - Parameters:
    ///   - command: The command, such as "mute".
    ///   - arguments: The whole command line, without the program's name.
    /// - Returns: The failure: exit 77.
    public static func notRoot(_ command: String, arguments: [String]) -> CommandLineFailure {
        let line = (["sudo", "macmonitor"] + arguments.map(shellQuoted)).joined(separator: " ")
        return CommandLineFailure(.noPermission, "'\(command)' needs root: \(TerminalSafeText.text(line))")
    }
    
    /// The failure a command line that can't be read stands for.
    ///
    /// - Parameter error: What ``CommandLineParser/parse(_:)`` threw.
    /// - Returns: The failure: 64, or 65 for a mute that can't be used (``CommandLineUsageError/exit``), with the
    ///   error's message and where to read more.
    public static func parsing(_ error: Error) -> CommandLineFailure {
        CommandLineFailure((error as? CommandLineUsageError)?.exit ?? .usage, "\(error)")
    }
    
    /// An argument as a shell reads it back: as typed when it has only characters a shell leaves alone, else in
    /// single quotes.
    ///
    /// - Parameter argument: The argument.
    /// - Returns: Such as `list`, or `'/Users/b/My App'`.
    static func shellQuoted(_ argument: String) -> String {
        let plain = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_./=:,+@%"))
        guard argument.isEmpty || !argument.unicodeScalars.allSatisfy(plain.contains) else { return argument }
        return "'" + argument.replacingOccurrences(of: "'", with: #"'\''"#) + "'"
    }
    
    /// The failure a Security Extension's reply stands for.
    ///
    /// - Parameter reply: The reply.
    /// - Returns: `nil` for ``StreamReply/Status-swift.enum/ok``, else the failure.
    public static func reply(_ reply: StreamReply) -> CommandLineFailure? {
        let problem = reply.problem.map { " \($0)" } ?? ""
        switch reply.status {
        case .ok:
            return nil
        case .invalid:
            return CommandLineFailure(.usage, "The Security Extension refused the request.\(problem)")
        case .unsupported:
            return CommandLineFailure(.unavailable, """
                The Security Extension (\(reply.sensorVersion)) is older than macmonitor. Open Mac Monitor to finish \
                updating its Security Extension.
                """)
        case .refused:
            return CommandLineFailure(.noPermission, "The Security Extension only streams to root.\(problem)")
        case .alreadyStreaming:
            return CommandLineFailure(.software, "The stream had already started.\(problem)")
        case .sessionLimit, .clientLimit:
            return CommandLineFailure(.temporaryFailure, reply.problem ?? "Too many streams are running.")
        case .notPermitted, .failed:
            return CommandLineFailure(.unavailable, reply.problem ?? "Endpoint Security refused the stream.")
        }
    }
    
    /// The failure a Security Extension's answer to a mute request stands for.
    ///
    /// - Parameter reply: The answer.
    /// - Returns: `nil` for `ok`, else the failure, with the Security Extension's reasons, or a sentence of its own
    ///   when it gave none.
    public static func reply(_ reply: MuteReply) -> CommandLineFailure? {
        let problems = reply.problems.joined(separator: " ")
        let failure = { (exit: CommandLineExit, fallback: String) in
            CommandLineFailure(exit, problems.isEmpty ? fallback : problems)
        }
        switch reply.status {
        case .ok: return nil
        case .refused: return failure(.noPermission, "The Security Extension refused the change.")
        case .notAdministrator: return failure(.noPermission, "Only an administrator can change the saved mute set.")
        case .invalid: return failure(.dataError, "The Security Extension refused the mutes: they can't be used.")
        case .storageFailed: return failure(.ioError, "The saved mute set couldn't be written, so nothing changed.")
        case .readOnly:
            return failure(.unavailable, "The saved mute set was written by a newer Mac Monitor. It can only be reset.")
        case .unsupported:
            return CommandLineFailure(.unavailable, """
                The Security Extension is older than macmonitor. Open Mac Monitor to finish updating its Security \
                Extension.
                """)
        }
    }
    
    /// The failure an XPC error stands for.
    ///
    /// - Parameters:
    ///   - error: The error from the connection's proxy.
    ///   - started: Had the Security Extension already answered? Then the connection going away means it stopped.
    /// - Returns: The failure: exit 69.
    public static func connection(_ error: Error, started: Bool) -> CommandLineFailure {
        let nsError = error as NSError
        let code = nsError.domain == NSCocoaErrorDomain ? XPCError(rawValue: nsError.code) : nil
        switch (code, started) {
        case (.codeSigningRequirementFailed?, _):
            return CommandLineFailure(.unavailable, """
                The Security Extension's code signature didn't match. Reinstall Mac Monitor.
                """)
        case (_, true):
            return stopped
        case (.invalid?, false):
            return CommandLineFailure(.unavailable, """
                Mac Monitor's Security Extension isn't running. Open Mac Monitor and allow its Security Extension.
                """)
        case (.interrupted?, false):
            return CommandLineFailure(.unavailable, """
                The Security Extension refused macmonitor. If Mac Monitor was just updated, open it once to finish \
                updating its Security Extension.
                """)
        default:
            return CommandLineFailure(.unavailable,
                                      "Couldn't reach the Security Extension: \(error.localizedDescription)")
        }
    }
    
    /// The Security Extension went away mid-stream: it was updated, turned off, or crashed.
    public static let stopped = CommandLineFailure(.unavailable, """
        The Security Extension stopped (it was updated, turned off, or exited). Run macmonitor again once Mac \
        Monitor shows it running.
        """)
    
    /// Standard output couldn't be written.
    ///
    /// - Parameter code: The write's `errno`.
    /// - Returns: The failure: exit 74.
    public static func output(_ code: Int32) -> CommandLineFailure {
        CommandLineFailure(.ioError, "Couldn't write the output: \(String(cString: strerror(code))).")
    }
    
    /// A file that can't be read.
    ///
    /// - Parameters:
    ///   - name: The file, as a message names it, such as “mutes.json” or "Standard input".
    ///   - error: Why: what opening or reading it threw.
    /// - Returns: The failure: exit 66, such as “mutes.json” couldn't be read: No such file or directory.
    public static func unreadable(_ name: String, because error: Error) -> CommandLineFailure {
        CommandLineFailure(.noInput, "\(name) couldn't be read: \(reason(error)).")
    }
    
    /// Why a file couldn't be read, in a few words.
    ///
    /// - Parameter error: What opening or reading it threw.
    /// - Returns: Such as "No such file or directory", or "it isn't a regular file" for a folder, pipe or device.
    static func reason(_ error: Error) -> String {
        if let posix = error as? POSIXError { return String(cString: strerror(posix.code.rawValue)) }
        if case .notAFile? = error as? TraceImporter.Failure { return "it isn't a regular file" }
        if (error as? CocoaError)?.code == .fileReadUnsupportedScheme { return "it isn't a regular file" }
        /// Foundation's errors for a file that can't be opened wrap the `errno` that says why.
        if let underlying = (error as NSError).userInfo[NSUnderlyingErrorKey] as? NSError,
           underlying.domain == NSPOSIXErrorDomain {
            return String(cString: strerror(Int32(underlying.code)))
        }
        return error.localizedDescription
    }
    
    /// Mac Monitor's telemetry schema can't be read or compiled: a bug in the build, since the framework bundles it.
    ///
    /// - Parameter error: Why, such as ``TelemetrySchemaError/missingResource``.
    /// - Returns: The failure: exit 70.
    public static func schema(_ error: Error) -> CommandLineFailure {
        CommandLineFailure(.software, error.localizedDescription)
    }
    
    /// The Security Extension didn't answer in time.
    public static let noAnswer = CommandLineFailure(.unavailable, "The Security Extension didn't answer.")
    
    /// The answer to "Continue?" was no.
    public static let declined = CommandLineFailure(.declined, "Nothing changed.")
    
    /// A change that asks first, with no terminal to ask at.
    ///
    /// - Parameter command: The command, such as "mute reset".
    /// - Returns: The failure: exit 64.
    public static func unconfirmed(_ command: String) -> CommandLineFailure {
        CommandLineFailure(.usage, """
            '\(command)' changes the saved mute set Mac Monitor and every stream follow, and there's no terminal to \
            ask at. Add --yes to go ahead.
            """)
    }
}
