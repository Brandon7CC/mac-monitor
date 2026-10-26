//
//  CommandLineCompletion.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/22/26.
//

import Foundation


// MARK: - Shells
/// The shells `macmonitor completion` writes a script for.
public enum CommandLineShell: String, CaseIterable, Sendable {
    case zsh, bash
}


// MARK: - Completion scripts
/// `macmonitor completion zsh|bash`: a script that completes `macmonitor`'s commands, options, their values and the
/// events this Mac can stream, made from the same lists the parser and its suggestions use (``CommandLineOption``).
public enum CommandLineCompletion {
    /// What one command, or one mute command, takes.
    struct Command {
        /// What's typed, such as "stream" or "mute add".
        let key: String
        /// Its options.
        let options: [CommandLineOption]
        /// What it takes besides options.
        let operands: [CommandLineOption.Value]

        /// - Parameters:
        ///   - key: What's typed.
        ///   - options: Its options.
        ///   - operands: What it takes besides options.
        init(_ key: String, _ options: [CommandLineOption] = [], _ operands: [CommandLineOption.Value] = []) {
            self.key = key
            self.options = options
            self.operands = operands
        }
    }

    /// Every command and mute command. A command added later doesn't build until it's described here.
    static var commands: [Command] {
        let described = CommandLineCommand.allCases.map { name -> Command in
            switch name {
            case .stream: return Command("stream", CommandLineOption.stream, [.choice(["all"]), .event])
            case .mute: return Command("mute", [], [.choice(MuteInvocation.Name.allCases.map(\.rawValue))])
            case .validate: return Command("validate", CommandLineOption.validate, [.file])
            case .help: return Command("help", [], [.choice(CommandLineCommand.allCases.map(\.rawValue))])
            case .completion: return Command("completion", [], [.choice(CommandLineShell.allCases.map(\.rawValue))])
            case .events, .schema, .version: return Command(name.rawValue)
            }
        }
        return described + MuteInvocation.Name.allCases.map { name in
            let takesPath = [.add, .remove, .import].contains(name)
            return Command("mute \(name.rawValue)", CommandLineOption.mute(name), takesPath ? [.file] : [])
        }
    }

    /// The commands whose second word is a command of their own: `mute`.
    static var parents: [String] {
        Set(commands.map(\.key).filter { $0.contains(" ") }.map { String($0.prefix { $0 != " " }) }).sorted()
    }

    /// The events this Mac's `macmonitor` streams, by short name, separated by spaces.
    static var events: String {
        CommandLineEvents.catalog().map(\.name).joined(separator: " ")
    }

    /// The script for a shell.
    ///
    /// - Parameter shell: The shell.
    /// - Returns: The script, ending in a newline.
    public static func script(for shell: CommandLineShell) -> String {
        switch shell {
        case .zsh: return zsh()
        case .bash: return bash()
        }
    }

    /// A word in single quotes for zsh and bash.
    ///
    /// - Parameter word: The word.
    /// - Returns: `'word'`, with each `'` in it closed, escaped and reopened.
    static func quoted(_ word: String) -> String {
        "'" + word.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// One `case` branch for a command.
    ///
    /// - Parameters:
    ///   - command: The command.
    ///   - complete: The shell's command that completes a value, or `nil` for a value it doesn't complete. An option
    ///     that takes a value gets a line that completes it, or completes nothing, and returns.
    ///   - rest: The lines that complete the command's options and operands.
    /// - Returns: The branch, indented for the script.
    private static func branch(_ command: Command, complete: (CommandLineOption.Value) -> String?,
                               rest: [String]) -> String {
        let values = command.options.filter { $0.value != .none }.map { option in
            "        \(option.name)) \(complete(option.value).map { "\($0); return" } ?? "return") ;;"
        }
        let previous = values.isEmpty ? [] : ["      case $previous in"] + values + ["      esac"]
        return (["    \(quoted(command.key)))"] + previous + rest.map { "      " + $0 } + ["      ;;"])
            .joined(separator: "\n")
    }
}


// MARK: - zsh
extension CommandLineCompletion {
    /// The zsh script: a completion function that works from a folder on `$fpath` and from `eval`.
    ///
    /// - Returns: The script.
    static func zsh() -> String {
        let summaries = CommandLineCommand.allCases.map { "      \(quoted("\($0.rawValue):\($0.help.summary)"))" }
        let cases = commands.map { command in
            /// The option names are offered as zsh offers any choice.
            let options = command.options.isEmpty ? [] : [CommandLineOption.Value.choice(command.options.map(\.name))]
            return branch(command, complete: \.zsh, rest: (options + command.operands).compactMap(\.zsh))
        }
        return """
            #compdef macmonitor
            # macmonitor's completion for zsh, from 'macmonitor completion zsh'. Save it as _macmonitor in a folder on
            # $fpath before compinit runs, or add 'eval "$(macmonitor completion zsh)"' to ~/.zshrc after it. The events
            # are those this Mac's macmonitor streams: write it again after updating Mac Monitor.

            _macmonitor() {
              local -a events=(\(events))
              local key=${words[2]} previous=${words[CURRENT-1]}
              if (( CURRENT == 2 )); then
                local -a commands=(
            \(summaries.joined(separator: "\n"))
                )
                _describe command commands
                return
              fi
              if (( CURRENT > 3 )) && [[ $key == (\(parents.joined(separator: "|"))) ]]; then
                key="$key ${words[3]}"
              fi
              case $key in
            \(cases.joined(separator: "\n"))
              esac
            }

            if [[ ${zsh_eval_context[-1]} == loadautofunc ]]; then
              _macmonitor "$@"
            else
              compdef _macmonitor macmonitor
            fi

            """
    }
}


// MARK: - bash
extension CommandLineCompletion {
    /// The bash script: a completion function for `complete`, for the bash 3.2 macOS ships and later. Where it
    /// completes nothing, bash completes file names.
    ///
    /// - Returns: The script.
    static func bash() -> String {
        let cases = commands.map { command -> String in
            let words = command.options.map(\.name) + command.operands.compactMap(\.bash)
            /// With a file operand, options are completed only after a dash, and bash completes the rest.
            let dash = command.operands.contains(.file) ? "[[ $cur == -* ]] && " : ""
            return branch(command, complete: { $0.bash.map(reply) },
                          rest: words.isEmpty ? [] : [dash + reply(words.joined(separator: " "))])
        }
        return """
            # macmonitor's completion for bash, from 'macmonitor completion bash'. Add
            # 'eval "$(macmonitor completion bash)"' to ~/.bash_profile. The events are those this Mac's macmonitor
            # streams: write it again after updating Mac Monitor.

            _macmonitor() {
              local cur=${COMP_WORDS[COMP_CWORD]} previous=${COMP_WORDS[COMP_CWORD-1]} key=${COMP_WORDS[1]}
              local events=\(quoted(events))
              COMPREPLY=()
              if (( COMP_CWORD == 1 )); then
                \(reply(CommandLineCommand.allCases.map(\.rawValue).joined(separator: " ")))
                return
              fi
              case $key in
                \(parents.joined(separator: "|"))) (( COMP_CWORD > 2 )) && key="$key ${COMP_WORDS[2]}" ;;
              esac
              case $key in
            \(cases.joined(separator: "\n"))
              esac
            }
            complete -o default -F _macmonitor macmonitor

            """
    }

    /// bash's command that offers the words that start with what's typed.
    ///
    /// - Parameter words: The words, separated by spaces. `$events` expands to the events.
    /// - Returns: `COMPREPLY=($(compgen -W "word…" -- "$cur"))`.
    private static func reply(_ words: String) -> String {
        "COMPREPLY=($(compgen -W \"\(words)\" -- \"$cur\"))"
    }
}


// MARK: - Option values
extension CommandLineOption.Value {
    /// zsh's command that offers the value, or `nil` for one zsh doesn't complete.
    var zsh: String? {
        switch self {
        case .none, .text: return nil
        case .choice(let words): return "compadd -- " + words.joined(separator: " ")
        case .event: return "compadd -a events"
        case .file: return "_files"
        }
    }

    /// The words bash offers for the value, separated by spaces, or `nil` for one it leaves to bash's file names or
    /// doesn't complete. `$events` expands to the events.
    var bash: String? {
        switch self {
        case .none, .text, .file: return nil
        case .choice(let words): return words.joined(separator: " ")
        case .event: return "$events"
        }
    }
}
