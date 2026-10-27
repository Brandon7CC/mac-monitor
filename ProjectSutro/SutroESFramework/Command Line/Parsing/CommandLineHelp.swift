//
//  CommandLineHelp.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Commands
/// Every command `macmonitor` has, by what's typed, in the order help lists them.
///
/// **Adding a command**: add its case here. The build then fails until ``help-swift.property`` describes it,
/// ``CommandLineParser/parse(_:)``, which switches over every case with no default, parses it into a new
/// ``CommandLineInvocation`` case, and `CommandLineTool.run` in `macmonitor` runs that case. A command that needs
/// neither root nor the Security Extension, as `schema` and `validate` don't, runs entirely in `macmonitor`.
public enum CommandLineCommand: String, CaseIterable, Sendable {
    case stream, mute, events, schema, validate, completion, version, help
    
    /// Does the command need root? Only what talks to the Security Extension does.
    public var requiresRoot: Bool {
        switch self {
        case .stream, .mute: return true
        case .events, .schema, .validate, .completion, .version, .help: return false
        }
    }
    
    /// Its help: one line for the command list, the usage line, and the rest, which may be empty.
    public var help: (summary: String, usage: String, details: String) {
        switch self {
        case .stream:
            return ("Stream Endpoint Security events until Ctrl-C, or for a time or a count.",
                    "sudo macmonitor stream [EVENT...] [--format text|jsonl|pretty] [--no-mutes] [--include-self] "
                        + "[--for DURATION] [--count N] [FILTER...]", """
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
                  --for DURATION    Stop after DURATION: seconds, or with a unit, such as 500ms, 30s, 5m or 1h.
                                    At most a year.
                  --count N         Stop after writing N events.

                Filters:
                  --pid PID               The initiating process's ID.
                  --process REGEX         The initiating process's executable path. For an exec, that's the
                                          program that called exec: --target is the one it runs.
                  --signing-id REGEX      The initiating process's signing ID.
                  --target REGEX          The event's target path, such as the program an exec runs or the
                                          file an open opens.
                  --grep REGEX            Any string in the event's record.
                  --predicate PREDICATE   An NSPredicate on the event's record, by its JSON key paths:
                                          'process.executable.path ENDSWITH "/curl"'
                                          'ANY event.exec.args CONTAINS[c] "token"'
                                          'process.audit_token.euid == 0 AND event_type == 9'

                A filter given more than once matches any of its values. --predicate is the exception. Every one \
                given must match. An event is written only if every filter given matches it. REGEX is found \
                anywhere in the value unless anchored with ^ or $, and is case-sensitive unless it starts with (?i). \
                The record is what --format jsonl writes ('macmonitor schema' describes it). --signing-id, --grep and \
                --predicate read it, so they make text output as slow as JSONL. Filtered events are never counted as \
                lost, and --count counts only events written.

                A stream stops at Ctrl-C, or at --for or --count, whichever comes first. Either way it writes every \
                event captured before it stopped, up to N, and exits 0 unless it was interrupted.

                Each stream has its own Endpoint Security clients in Mac Monitor's Security Extension, so Mac Monitor \
                keeps recording while it runs. At most \(SensorXPC.maxCommandLineStreams) streams run at once. \
                Events lost because Endpoint Security or macmonitor fell behind are counted and reported on standard \
                error.
                """)
        case .mute:
            return ("Show or change the saved mute set Mac Monitor and macmonitor share.",
                    "sudo macmonitor mute " + MuteInvocation.Name.allCases.map(\.rawValue).joined(separator: "|"), """
                Commands:
                  list [--format text|json]               Show the saved mute set: a table, or with --format json
                                                          the mute file export writes.
                  add PATH [--type TYPE] [--event EVENT]...
                                                          Mute a path, for every event or only the events named.
                  remove PATH [--type TYPE] [--event EVENT]...
                                                          Unmute a path, or only the events named.
                  import FILE|- [--merge] [--yes]         Make a mute file's mutes the saved set, or with --merge add
                                                          them to it. Reads Mac Monitor mute files and the lists Mac
                                                          Monitor exported before 3.0. - reads standard input.
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
                """)
        case .events:
            return ("List the events macmonitor can stream.", "macmonitor events", """
                Each event's short name, then its full name. Events marked * are streamed when no EVENT \
                is given. On a terminal, a line at the end says so.
                """)
        case .schema:
            return ("Print Mac Monitor's telemetry schema.", "macmonitor schema", """
                Writes the JSON Schema (draft 2020-12) of every record Mac Monitor and macmonitor write, telemetry \
                \(TelemetrySchema.version), byte for byte as Mac Monitor ships it. Save it with 'macmonitor schema > \
                \(TelemetrySchema.fileName)'.
                """)
        case .validate:
            return ("Check a trace against the telemetry schema.", "macmonitor validate [--eslogger] TRACE", """
                TRACE is a file Mac Monitor or macmonitor exported: JSON Lines, pretty records, or a JSON array. It \
                must be a regular file, not a folder, a pipe, or standard input.

                Options:
                  --eslogger   Check only the keys eslogger writes: for eslogger's own JSON.

                The report gives the number of valid, invalid and malformed records, how many issues of each kind \
                there are, and the first \(ValidateCommand.issueLimit) issues, each with the line its record starts \
                on and the path of the value. macmonitor exits 0 when every record follows the schema, 65 when a \
                record doesn't or isn't JSON or TRACE has no records, and 66 when TRACE can't be read. Ctrl-C stops \
                checking, prints the report so far, and exits 130.
                """)
        case .completion:
            return ("Print a shell completion script.", "macmonitor completion zsh|bash", """
                Completes commands, options, their values, and the events this Mac's macmonitor streams. Write it \
                again after updating Mac Monitor.

                  zsh    Save it as _macmonitor in a folder on $fpath, before compinit runs:
                           macmonitor completion zsh > ~/.zsh/completions/_macmonitor
                         with fpath=(~/.zsh/completions $fpath) in ~/.zshrc. Or add
                         eval "$(macmonitor completion zsh)" to ~/.zshrc, after compinit.
                  bash   Add eval "$(macmonitor completion bash)" to ~/.bash_profile.
                """)
        case .version: return ("Show macmonitor's version.", "macmonitor version", "")
        case .help: return ("Show help for a command.", "macmonitor help [COMMAND]", "")
        }
    }
}


// MARK: - Help
/// `macmonitor`'s help text: each ``CommandLineCommand``'s, the overview that lists them, and the `events` listing.
public enum CommandLineHelp {
    /// Help for a command, or for `macmonitor`.
    ///
    /// - Parameter name: The command, or `nil` for the overview.
    /// - Returns: The text, ending in a newline.
    public static func text(for name: String?) -> String {
        guard let command = name.flatMap(CommandLineCommand.init(rawValue:)) else { return overview() }
        let (summary, usage, details) = command.help
        return "Usage: \(usage)\n\n\(summary)\n\(details.isEmpty ? "" : "\n\(details)\n")"
    }
    
    /// `macmonitor`'s overview.
    ///
    /// - Returns: The text, ending in a newline.
    static func overview() -> String {
        let commands = CommandLineCommand.allCases
        let width = commands.map(\.rawValue.count).max() ?? 0
        let list = commands.map { command in
            let name = command.rawValue
            return "  \(name.padding(toLength: width, withPad: " ", startingAt: 0))   \(command.help.summary)"
        }
        let rooted = commands.filter(\.requiresRoot).map(\.rawValue).joined(separator: " and ")
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
    /// - Parameter legend: End with a line saying what `*` means: for a terminal, where no script reads the list.
    /// - Returns: The text, one event a line.
    public static func eventList(legend: Bool = false) -> String {
        let catalog = CommandLineEvents.catalog()
        let width = catalog.map(\.name.count).max() ?? 0
        let lines = catalog.map { event in
            "\(event.isDefault ? "*" : " ") \(event.name.padding(toLength: width, withPad: " ", startingAt: 0))  "
                + event.fullName
        }
        return (lines + (legend ? ["", "* streamed by 'sudo macmonitor stream' with no EVENT"] : []))
            .joined(separator: "\n") + "\n"
    }
}
