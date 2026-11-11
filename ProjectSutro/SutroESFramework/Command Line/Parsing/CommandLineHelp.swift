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
    case stream, mute, indicators, status, events, schema, validate, completion, version, help
    
    /// Does the command need root? Only what talks to the Security Extension does, and then the Security Extension
    /// decides: root always, and any user when Mac Monitor's Settings allows it (``CommandLineAccess``).
    public var requiresRoot: Bool {
        switch self {
        case .stream, .mute, .indicators: return true
        case .status, .events, .schema, .validate, .completion, .version, .help: return false
        }
    }
    
    /// Its help: one line for the command list, the usage line, and the rest, which may be empty.
    public var help: (summary: String, usage: String, details: String) {
        switch self {
        case .stream:
            return ("Stream Endpoint Security events until Ctrl-C, or for a time or a count.",
                    "sudo macmonitor stream [EVENT...] [--format text|jsonl|pretty] [--no-mutes] [--include-self] "
                        + "[--every EVENT] [--for DURATION] [--count N] [FILTER...]", """
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
                  --every EVENT     Stream every EVENT, not only those Mac Monitor keeps by default. With no
                                    --every, close streams only closes of modified files. --every all turns every
                                    such default off.
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
                  --indicator NAME|ID     An indicator the event matched, by its name, ignoring case, or its
                                          ID, as 'macmonitor indicators list' shows them:
                                          --indicator 'Plist modified'.

                A filter given more than once matches any of its values. --predicate is the exception. Every one \
                given must match. An event is written only if every filter given matches it. REGEX is found \
                anywhere in the value unless anchored with ^ or $, and is case-sensitive unless it starts with (?i). \
                The record is what --format jsonl writes ('macmonitor schema' describes it). Its indicators key lists \
                the indicators in this Mac's set ('macmonitor indicators') that the Security Extension matched as it \
                captured the event. A Security Extension older than 3.1 matches none and leaves the key out, \
                and --indicator then stops the stream. --signing-id, --grep, --predicate and --indicator read the \
                record, so they make text output as slow as JSONL. Filtered events are never counted as \
                lost, and --count counts only events written. Closes left out as unmodified are never counted as lost \
                either: the closing line says how many there were. A file changed only through a writable mapping \
                closes unmodified, and mmap events show such mappings. Mac Monitor's own Settings choice doesn't \
                change a stream's.

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
                  update [--yes]                          Merge a newer Mac Monitor's default set into a saved set
                                                          you've changed, keeping your changes. A saved set you
                                                          haven't changed is updated on upgrade by itself.
                
                import, reset and update say what they'd change and ask first. --yes goes ahead without asking, and is \
                needed when there's no terminal to ask at.
                
                PATH is absolute. TYPE is literal (the default), prefix, target-literal, or target-prefix: literal \
                and prefix match the process's executable, the target types the event's target path. EVENT is a \
                NOTIFY event's short or full name.
                
                The saved set lives in the Security Extension. It applies to Mac Monitor and to every stream without \
                --no-mutes, including streams already running, and survives restarts. Muted events are never \
                captured, so they never show as lost.
                """)
        case .indicators:
            return ("Show or change the indicators the Security Extension runs on every event.",
                    "sudo macmonitor indicators " + IndicatorInvocation.Name.allCases.map(\.rawValue)
                        .joined(separator: "|"), """
                Commands:
                  list [--format text|json]               Show this Mac's indicators: a table, or with --format json
                                                          (--json for short) the indicator file export writes.
                  show ID|NAME...                         Show every detail of indicators: state, severity, tactic,
                                                          technique, description and predicate.
                  add --name NAME --predicate PREDICATE [--severity SEVERITY]
                                                          Add an indicator of your own: medium unless SEVERITY says.
                  edit ID|NAME [--name NAME] [--predicate PREDICATE] [--severity SEVERITY]
                       [--description TEXT] [--tactic TACTIC|none] [--technique TECHNIQUE|none]
                       [--symbol SYMBOL]                  Change an indicator's fields, Mac Monitor's own included.
                  edit ID|NAME --file FILE|- [--yes]      Change an indicator as one exported indicator says: the
                                                          editable keys it has, the rest ignored.
                  edit ID|NAME --restore                  Put one of Mac Monitor's own back as this build ships it.
                  import FILE|- [--replace] [--yes]       Add an indicator file's indicators, replacing those with
                                                          the same ID, or with --replace make the set exactly them.
                                                          Reads files Mac Monitor's Settings > Indicators exports.
                                                          - reads standard input.
                  remove ID|NAME...                       Remove indicators, Mac Monitor's own included.
                  enable ID|NAME...                       Turn indicators on.
                  disable ID|NAME...                      Turn indicators off.
                  export [ID|NAME...]                     Write the set, or the indicators named, as an indicator
                                                          file to standard output.

                import and edit --file say what they would change, Mac Monitor's own indicators they would remove, \
                turn off or replace among them, and ask first. --yes goes ahead without asking, and is needed when \
                there's no terminal to ask at.

                edit keeps an indicator's ID, so earlier records, streams following it with --indicator ID, and each \
                user's table marks stay with it. It never turns an indicator on or off, and never changes how \
                anyone's tables mark it. Records already captured keep the name and severity they had; a search by \
                indicators.id finds them across a rename, indicators.name doesn't. A name another indicator has is \
                refused. --file takes the editable keys present in one exported indicator (name, description, \
                symbol, color, predicate, tactic, technique and severity) and ignores the rest, \
                such as isEnabled; 'macmonitor indicators export ID > one.json' writes one to start from. TACTIC is \
                an ATT&CK tactic in any case, by name, ID or as the JSON writes it: "Defense Evasion", TA0005 or \
                defenseEvasion. TECHNIQUE is one such as T1059.002. none clears either. SYMBOL is an SF Symbol's \
                name, which macmonitor can't check: Mac Monitor shows its plain symbol for one it doesn't know. \
                Editing the rule of one of Mac Monitor's own, not just its tactic, technique or severity, stops Mac \
                Monitor updates changing it, until edit --restore.

                NAME is an indicator's name, ignoring case, and ID its identity, as list shows them. A name two \
                indicators share is refused: use the ID. PREDICATE is an NSPredicate on an event's record, as \
                'macmonitor stream --predicate' takes one, that names its event types by their payloads or by \
                es_event_type, such as 'event.exec != nil AND process.executable.path ENDSWITH "/curl"'. \
                SEVERITY is low, medium or high: how strong a sign of something malicious a match is. It doesn't \
                change what matches.

                The set lives in the Security Extension, which matches it against every event it captures for Mac \
                Monitor and for every stream, --no-mutes included, and lists the matches in each record's \
                indicators key. A change applies at once, to every user and every stream already running, and \
                survives restarts. An indicator the Security Extension can't run is kept, and list says why.
                """)
        case .status:
            return ("Show what's installed, what it needs, and who is capturing.", "macmonitor status [--json]", """
                Shows the versions of macmonitor, Mac Monitor and its Security Extension, whether the Security \
                Extension is activated and has Full Disk Access, whether Mac Monitor is connected and recording, how \
                many macmonitor streams are running. It needs no root, and changes nothing.

                Options:
                  --json   Write JSON, for a script. A part that isn't known is null.

                It exits 0 when the Security Extension is activated and Endpoint Security lets it capture, and \
                \(CommandLineExit.unavailable.rawValue) when it isn't ready, after showing why.
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
            return ("Set up Tab completion, or print its script.", "macmonitor completion zsh|bash", """
                On a terminal, it shows the line that turns Tab completion on. Read by eval, piped or redirected, \
                it writes the script, which completes commands, options, their values, and the events this Mac's \
                macmonitor streams.

                  zsh    Add eval "$(macmonitor completion zsh)" to ~/.zshrc. It starts compinit if nothing
                         has. Or save the script as _macmonitor in a folder on $fpath, before compinit runs:
                           macmonitor completion zsh > ~/.zsh/completions/_macmonitor
                         with fpath=(~/.zsh/completions $fpath) in ~/.zshrc. Save it again after
                         updating Mac Monitor.
                  bash   Add eval "$(macmonitor completion bash)" to ~/.bash_profile.
                """)
        case .version:
            return ("Show macmonitor's version.", "macmonitor version", """
                'macmonitor -v' and 'macmonitor --version' do the same. As root, it shows the Security Extension's \
                version too. 'macmonitor status' shows every version without root.
                """)
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
        let rooted = commands.filter(\.requiresRoot).map(\.rawValue)
        let named = rooted.count > 1 ? rooted.dropLast().joined(separator: ", ") + " and " + (rooted.last ?? "")
            : rooted.joined()
        return """
            macmonitor streams Endpoint Security events from Mac Monitor's Security Extension, and checks traces \
            against Mac Monitor's telemetry schema.

            Usage: macmonitor <command> [options]

            Commands:
            \(list.joined(separator: "\n"))

            Run 'macmonitor help <command>' for a command's options. \(named) need root: run them with sudo, or \
            allow them without sudo in \(CommandLineAccess.setting).

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
