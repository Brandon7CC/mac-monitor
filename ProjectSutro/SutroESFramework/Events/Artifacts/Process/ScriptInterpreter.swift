//
//  ScriptInterpreter.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - Scripting interpreters
/// A scripting interpreter whose script Mac Monitor looks for among an exec's arguments, and the options it reads
/// before that script.
///
/// ES only names the script of an exec that runs one directly (`./tool.sh`), not one handed to its interpreter
/// (`bash tool.sh`). An interpreter's options decide which argument is the script, if any: in
/// `python3 -c 'code' data.json` or `bash -lc : notes.txt` the code is on the command line, and the file after it is
/// data the code reads.
struct ScriptInterpreter {
    /// The executable's name without a version: `python` for `python3.12`.
    let name: String
    /// Short options after which the script isn't a file Mac Monitor can name: code on the command line (`-c`, `-e`),
    /// a module (`python3 -m`), standard input (`bash -s`), or a script found on `PATH` (`ruby -S`).
    var noScriptFlags: Set<Character> = []
    /// Short options whose value is the rest of their argument or else the next argument (`-o pipefail`, `-Wignore`).
    var valueFlags: Set<Character> = []
    /// Short options whose optional value can only be the rest of their argument (`perl -i.bak`, `-Mstrict`).
    var attachedValueFlags: Set<Character> = []
    /// Short options whose value is the script (`expect -f tool.exp`).
    var scriptFlags: Set<Character> = []
    /// Whole options after which the script isn't a file Mac Monitor can name (`--eval`), also written
    /// `--eval=code`.
    var noScriptOptions: Set<String> = []
    /// Whole options whose value is the next argument (`--rcfile file`). Written `--rcfile=file`, they're one argument.
    var valueOptions: Set<String> = []
    /// Do short options combine in one argument (`-lc` is `-l -c`)? Swift's are words instead (`-module-name`).
    var clusters = true
    /// Do options also start with "+" (`bash +o posix`)?
    var plusOptions = false
    /// Words that can come before the script (`bun run app.ts`).
    var subcommands: Set<String> = []
    /// Does a lone "-" end the options, as "--" does (`bash - tool.sh` runs `tool.sh`)? Otherwise it's standard input.
    var dashEndsOptions = false
    /// Does any option but a ``valueOptions`` one mean there's no script? `tclsh` only runs a file named first, or
    /// after `-encoding name`: with another option first, even `--`, it reads standard input.
    var otherOptionsMeanNoScript = false
}


// MARK: - Supported interpreters
extension ScriptInterpreter {
    /// A Bourne-style shell, which takes code with `-c`, reads standard input with `-s`, sets options with `-o` and
    /// `+o`, and ends its options with "-" as well as "--".
    ///
    /// - Parameters:
    ///   - name: The shell's name.
    ///   - valueFlags: Its options that take a value, `o` among them.
    ///   - valueOptions: Its long options that take a value.
    /// - Returns: The shell.
    private static func shell(_ name: String, valueFlags: Set<Character> = ["o"],
                              valueOptions: Set<String> = []) -> ScriptInterpreter {
        ScriptInterpreter(name: name, noScriptFlags: ["c", "s"], valueFlags: valueFlags, valueOptions: valueOptions,
                          plusOptions: true, dashEndsOptions: true)
    }

    /// The interpreters Mac Monitor looks for a script for, with their options as `man` and `--help` list them on
    /// macOS 27. `sh` isn't one: `/bin/sh` runs the shell `/private/var/select/sh` names (`bash`) in the same process,
    /// so that exec is the one whose script is read.
    static let supported: [ScriptInterpreter] = [
        shell("bash", valueFlags: ["o", "O"], valueOptions: ["--rcfile", "--init-file"]),
        shell("zsh", valueOptions: ["--emulate"]),
        shell("dash"),
        shell("ksh", valueFlags: ["o", "R"]),
        /// `-t` runs one line of standard input. `-e` exits on an error: it isn't code. A lone "-" is a file's name.
        ScriptInterpreter(name: "csh", noScriptFlags: ["c", "s", "t"]),
        ScriptInterpreter(name: "tcsh", noScriptFlags: ["c", "s", "t"]),
        ScriptInterpreter(name: "python", noScriptFlags: ["c", "m"], valueFlags: ["W", "X"],
                          valueOptions: ["--check-hash-based-pycs"]),
        ScriptInterpreter(name: "perl", noScriptFlags: ["e", "E", "S"], valueFlags: ["I"],
                          attachedValueFlags: ["C", "d", "D", "F", "i", "m", "M", "V", "x"]),
        /// `--backtrace-limit` is a newer Ruby's (3.0 and later), such as Homebrew's.
        ScriptInterpreter(name: "ruby", noScriptFlags: ["e", "S"], valueFlags: ["C", "E", "I", "r"],
                          attachedValueFlags: ["F", "i", "K", "T", "W", "x"],
                          valueOptions: ["--enable", "--disable", "--encoding", "--external-encoding",
                                         "--internal-encoding", "--dump", "--backtrace-limit"]),
        ScriptInterpreter(name: "osascript", noScriptFlags: ["e"], valueFlags: ["l", "s"]),
        ScriptInterpreter(name: "node", noScriptFlags: ["e", "p"], valueFlags: ["r", "C"],
                          noScriptOptions: ["--eval", "--print", "--run"],
                          valueOptions: ["--require", "--import", "--loader", "--experimental-loader", "--input-type",
                                         "--conditions", "--env-file", "--env-file-if-exists", "--title"]),
        ScriptInterpreter(name: "bun", noScriptFlags: ["e", "p"], valueFlags: ["r"],
                          noScriptOptions: ["--eval", "--print"], valueOptions: ["--preload", "--cwd"],
                          subcommands: ["run"]),
        ScriptInterpreter(name: "swift", noScriptOptions: ["-e"],
                          valueOptions: ["-D", "-F", "-I", "-j", "-L", "-l", "-Xcc", "-Xlinker", "-Xfrontend",
                                         "-module-name", "-sdk", "-target", "-swift-version", "-language-mode",
                                         "-module-cache-path", "-resource-dir", "-libc", "-locale"],
                          clusters: false),
        /// `tclsh ?-encoding name? ?fileName arg ...?`
        ScriptInterpreter(name: "tclsh", valueOptions: ["-encoding"], clusters: false, otherOptionsMeanNoScript: true),
        /// `expect -c cmds` runs the commands before the script, so the script can still follow.
        ScriptInterpreter(name: "expect", valueFlags: ["c", "D"], scriptFlags: ["f", "b"]),
    ]

    /// The supported interpreter an executable is: one of ``supported``, alone or followed by a version (`python3`,
    /// `python3.12`, `tclsh8.5`). Names that only start with one (`bundle`, `bunzip2`, `swift-frontend`) aren't.
    ///
    /// - Parameter executableName: The executable's file name.
    /// - Returns: The interpreter, or `nil` when it isn't one.
    static func named(_ executableName: String) -> ScriptInterpreter? {
        supported.first { interpreter in
            guard executableName.hasPrefix(interpreter.name) else { return false }
            return executableName.dropFirst(interpreter.name.count).allSatisfy { $0.isNumber || $0 == "." }
        }
    }
}


// MARK: - Indicator the script argument
extension ScriptInterpreter {
    /// What a cluster of short options (`-lc`, `-pi.bak`) means for the script.
    private enum ClusterMeaning {
        /// Only options: the script is still to come.
        case options
        /// The next argument is an option's value.
        case valueNext
        /// The script isn't a file Mac Monitor can name.
        case noScript
        /// The script is this option's value: the rest of the argument, or else the next one when `nil`.
        case script(String?)
    }

    /// The argument that names the script, as the interpreter reads its arguments: the first one that isn't an
    /// option or an option's value.
    ///
    /// - Parameter arguments: The arguments after the executable's own (`argv[0]`).
    /// - Returns: The argument as written, or `nil` when the script isn't a file named there: code on the command line,
    ///   standard input (`-`, except to a shell), or no argument at all.
    func scriptArgument<Arguments: Collection>(in arguments: Arguments) -> String? where Arguments.Element == String {
        var remaining = arguments[...]
        var subcommands = self.subcommands
        while let argument = remaining.popFirst() {
            if otherOptionsMeanNoScript, argument.hasPrefix("-"), !valueOptions.contains(argument) { return nil }
            if argument == "--" || (dashEndsOptions && argument == "-") { return remaining.first }
            if argument == "-" { return nil }
            if noScriptOptions.contains(where: { argument == $0 || argument.hasPrefix($0 + "=") }) { return nil }
            if valueOptions.contains(argument) {
                remaining = remaining.dropFirst()
                continue
            }
            guard argument.count > 1, argument.hasPrefix("-") || (plusOptions && argument.hasPrefix("+")) else {
                if subcommands.remove(argument) != nil { continue }
                return argument
            }
            guard clusters, !argument.hasPrefix("--") else { continue }
            switch meaning(ofCluster: argument.dropFirst()) {
            case .options: continue
            case .valueNext: remaining = remaining.dropFirst()
            case .noScript: return nil
            case .script(let value): return value ?? remaining.first
            }
        }
        return nil
    }

    /// What a cluster of short options means for the script. An option that takes a value ends the cluster: the rest
    /// is its value (`-Wignore`, `perl -i.e`), not more options.
    ///
    /// - Parameter cluster: The options, without their leading "-" or "+".
    /// - Returns: Whether the script is still to come, follows a value, isn't a file, or is an option's value.
    private func meaning(ofCluster cluster: Substring) -> ClusterMeaning {
        for (offset, flag) in cluster.enumerated() {
            if noScriptFlags.contains(flag) { return .noScript }
            let rest = cluster.dropFirst(offset + 1)
            if scriptFlags.contains(flag) { return .script(rest.isEmpty ? nil : String(rest)) }
            if valueFlags.contains(flag) { return rest.isEmpty ? .valueNext : .options }
            if attachedValueFlags.contains(flag) { return .options }
        }
        return .options
    }
}
