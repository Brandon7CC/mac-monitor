//
//  CommandLineHelp.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Commands
/// One `macmonitor` command, as its help describes it.
public struct CommandLineCommand: Equatable {
    /// Every command `macmonitor` has, by what's typed.
    ///
    /// **Adding a command**: add its case here. The build then fails until ``CommandLineParser/parse(_:)``, which
    /// switches over every case with no default, parses it into a new ``CommandLineInvocation`` case, and
    /// `CommandLineTool.run` in `macmonitor` runs that case. ``CommandLineHelp/commands`` must describe each case once,
    /// which the tests check. A command that needs neither root nor the Security Extension, as `schema` and `validate`
    /// don't, runs entirely in `macmonitor`.
    public enum Name: String, CaseIterable, Sendable {
        case stream, mute, events, schema, validate, version, help
        
        /// Does the command need root? Only what talks to the Security Extension does.
        public var requiresRoot: Bool {
            switch self {
            case .stream, .mute: return true
            case .events, .schema, .validate, .version, .help: return false
            }
        }
    }
    
    /// Which command.
    public let id: Name
    /// One line for the command list.
    public let summary: String
    /// The usage line.
    public let usage: String
    /// The rest of its help.
    public let details: String
    
    /// What's typed, such as "stream".
    public var name: String { id.rawValue }
    /// Does it need root?
    public var requiresRoot: Bool { id.requiresRoot }
}


// MARK: - Help
/// `macmonitor`'s commands and help text.
///
/// Every ``CommandLineCommand/Name-swift.enum`` has one ``CommandLineCommand`` here, a case in
/// ``CommandLineParser``, and a ``CommandLineInvocation`` case (see ``CommandLineCommand/Name-swift.enum``).
public enum CommandLineHelp {
    /// Every command, in the order help lists them: one for each ``CommandLineCommand/Name-swift.enum``.
    public static let commands: [CommandLineCommand] = [
        CommandLineCommand(
            id: .stream, summary: "Stream Endpoint Security events until Ctrl-C.",
            usage: "sudo macmonitor stream [EVENT...] [--format text|jsonl|pretty] [--no-mutes] [--include-self]",
            details: """
                EVENT is a short name (exec), a full name (ES_EVENT_TYPE_NOTIFY_EXEC), or all. With no EVENT, \
                macmonitor streams the events Mac Monitor records by default. Run 'macmonitor events' to list them.

                Options:
                  --format text     One line per event: the default on a terminal. --text for short.
                  --format jsonl    One record per line, the same as Mac Monitor's Export telemetry > JSONL (lines)
                                    menu: an eslogger superset. The default when piped or redirected. --json for
                                    short.
                  --format pretty   The same records pretty-printed, like Export telemetry > JSON (pretty).
                                    Easier to read in a terminal. --pretty for short.
                  --no-mutes        Don't apply the saved mute set that Mac Monitor and macmonitor share.
                  --include-self    Show the events of macmonitor's own pipeline, such as jq's.

                Each stream has its own Endpoint Security clients in Mac Monitor's Security Extension, so Mac Monitor \
                keeps recording while it runs. At most \(SensorXPC.maxCommandLineStreams) streams run at once. \
                Events lost because Endpoint Security or macmonitor fell behind are counted and reported on standard \
                error.
                """),
        CommandLineCommand(
            id: .mute, summary: "Show or change the saved mute set Mac Monitor and macmonitor share.",
            usage: "sudo macmonitor mute " + MuteInvocation.Name.allCases.map(\.rawValue).joined(separator: "|"),
            details: """
                Commands:
                  list [--format text|json]               Show the saved mute set: a table, or with --format json
                                                          the mute file export writes.
                  add PATH [--type TYPE] [--event EVENT]...
                                                          Mute a path, for every event or only the events named.
                  remove PATH [--type TYPE] [--event EVENT]...
                                                          Unmute a path, or only the events named.
                  import FILE|- [--merge] [--yes]         Make a mute file's mutes the saved set, or with --merge add
                                                          them to it. Reads Mac Monitor mute files and the lists Mac
                                                          Monitor exported before 2.2. - reads standard input.
                  export                                  Write the saved set as a mute file to standard output.
                  reset [--yes]                           Restore Mac Monitor's default set. Its mutes for a home
                                                          folder's caches and Biome streams are for the user logged
                                                          in at the console.
                
                import and reset say what they'd change and ask first. --yes goes ahead without asking, and is \
                needed when there's no terminal to ask at.
                
                PATH is absolute. TYPE is literal (the default), prefix, target-literal, or target-prefix: literal \
                and prefix match the process's executable, the target types the event's target path. EVENT is a \
                NOTIFY event's short or full name.
                
                The saved set lives in the Security Extension. It applies to Mac Monitor and to every stream without \
                --no-mutes, including streams already running, and survives restarts. Muted events are never \
                captured, so they never show as lost.
                """),
        CommandLineCommand(id: .events, summary: "List the events macmonitor can stream.",
                           usage: "macmonitor events",
                           details: "Events marked * are streamed when no EVENT is given."),
        CommandLineCommand(
            id: .schema, summary: "Print Mac Monitor's telemetry schema.", usage: "macmonitor schema",
            details: """
                Writes the JSON Schema (draft 2020-12) of every record Mac Monitor and macmonitor write, telemetry \
                \(TelemetrySchema.version), byte for byte as Mac Monitor ships it. Save it with 'macmonitor schema > \
                \(TelemetrySchema.fileName)'.
                """),
        CommandLineCommand(
            id: .validate, summary: "Check a trace against the telemetry schema.",
            usage: "macmonitor validate [--eslogger] TRACE",
            details: """
                TRACE is a file Mac Monitor or macmonitor exported: JSON Lines, pretty records, or a JSON array. It \
                must be a regular file, not a folder, a pipe, or standard input.

                Options:
                  --eslogger   Check only the keys eslogger writes: for eslogger's own JSON.

                The report gives the number of valid, invalid and malformed records, how many issues of each kind \
                there are, and the first \(ValidateCommand.issueLimit) issues, each with the line its record starts \
                on and the path of the value. macmonitor exits 0 when every record follows the schema, 65 when a \
                record doesn't or isn't JSON or TRACE has no records, and 66 when TRACE can't be read. Ctrl-C stops \
                checking, prints the report so far, and exits 130.
                """),
        CommandLineCommand(id: .version, summary: "Show macmonitor's version.", usage: "macmonitor version",
                           details: ""),
        CommandLineCommand(id: .help, summary: "Show help for a command.", usage: "macmonitor help [COMMAND]",
                           details: "")
    ]
    
    /// A command by name.
    ///
    /// - Parameter name: What's typed.
    /// - Returns: The command, or `nil` if there's none.
    public static func command(named name: String) -> CommandLineCommand? {
        commands.first { $0.name == name }
    }
    
    /// Help for a command, or for `macmonitor`.
    ///
    /// - Parameter name: The command, or `nil` for the overview.
    /// - Returns: The text, ending in a newline.
    public static func text(for name: String?) -> String {
        guard let name, let command = command(named: name) else { return overview() }
        let details = command.details.isEmpty ? "" : "\n\(command.details)\n"
        return "Usage: \(command.usage)\n\n\(command.summary)\n\(details)"
    }
    
    /// `macmonitor`'s overview.
    ///
    /// - Returns: The text, ending in a newline.
    static func overview() -> String {
        let width = commands.map(\.name.count).max() ?? 0
        let list = commands.map { command in
            "  \(command.name)\(String(repeating: " ", count: width - command.name.count))   \(command.summary)"
        }
        let rooted = commands.filter(\.requiresRoot).map(\.name).joined(separator: " and ")
        return """
            macmonitor streams Endpoint Security events from Mac Monitor's Security Extension, and checks traces \
            against Mac Monitor's telemetry schema.

            Usage: macmonitor <command> [options]

            Commands:
            \(list.joined(separator: "\n"))

            Run 'macmonitor help <command>' for a command's options. \(rooted) need root: run them with sudo.

            """
    }
    
    /// The `events` listing: each event's short and full name, defaults marked `*`.
    ///
    /// - Returns: The text, one event a line.
    public static func eventList() -> String {
        let catalog = CommandLineEvents.catalog()
        let width = catalog.map(\.name.count).max() ?? 0
        return catalog.map { event in
            "\(event.isDefault ? "*" : " ") \(event.name)\(String(repeating: " ", count: width - event.name.count))  "
                + event.fullName
        }.joined(separator: "\n") + "\n"
    }
}
