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
/// data the code reads. That code is read too (``inlineCode(in:executableName:)``). Both read the arguments with one
/// ``ArgumentReader``.
struct ScriptInterpreter {
    /// The executable's name without a version: `python` for `python3.12`.
    let name: String
    /// The options that give code on the command line (`-c`, `-e`, `--eval`), when Mac Monitor reads that code. The
    /// script isn't a file after them either.
    var code: CodeOptions? = nil
    /// Other short options after which the script isn't a file Mac Monitor can name: a module (`python3 -m`),
    /// standard input (`bash -s`), a script found on `PATH` (`ruby -S`), or code Mac Monitor doesn't read (`bun -e`).
    var noScriptFlags: Set<Character> = []
    /// Short options whose value is the rest of their argument or else the next argument (`zsh -o pipefail`,
    /// `-Wignore`).
    var valueFlags: Set<Character> = []
    /// Short options whose value is the next argument, while the rest of their argument is more options
    /// (`bash -oc pipefail code`). Each takes the next argument left in turn (`bash -oo pipefail errexit`).
    var nextValueFlags: Set<Character> = []
    /// Short options whose optional value can only be the rest of their argument (`perl -i.bak`, `-Mstrict`).
    var attachedValueFlags: Set<Character> = []
    /// Short options whose value is the script (`expect -f tool.exp`).
    var scriptFlags: Set<Character> = []
    /// Short options that end the options after their own argument, so every argument left is an operand
    /// (`tcsh -b -c` runs a file named `-c`).
    var endFlags: Set<Character> = []
    /// Other whole options after which the script isn't a file Mac Monitor can name (`node --run`), also written
    /// `--run=name`.
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
    /// A Bourne-style shell, which runs its first argument that isn't an option as code with `-c`, reads standard
    /// input with `-s`, sets options with `-o` and `+o`, and ends its options with "-" as well as "--".
    ///
    /// - Parameters:
    ///   - name: The shell's name.
    ///   - valueFlags: Its options whose value is the rest of their argument or else the next one.
    ///   - nextValueFlags: Its options whose value is the next argument.
    ///   - valueOptions: Its long options that take a value.
    ///   - endFlags: Its options that end the options after their cluster.
    /// - Returns: The shell.
    private static func shell(_ name: String, valueFlags: Set<Character> = [], nextValueFlags: Set<Character> = [],
                              valueOptions: Set<String> = [], endFlags: Set<Character> = []) -> ScriptInterpreter {
        ScriptInterpreter(name: name, code: CodeOptions(flags: ["c"], form: .operand, language: .shell),
                          noScriptFlags: ["s"], valueFlags: valueFlags, nextValueFlags: nextValueFlags,
                          endFlags: endFlags, valueOptions: valueOptions, plusOptions: true, dashEndsOptions: true)
    }

    /// bash, whose `-o` and `-O` take the next argument wherever they are in their cluster, as dash's `-o` does.
    ///
    /// - Parameter name: The name it runs as: `bash`, or `sh` (``sh``).
    /// - Returns: The shell.
    private static func bash(named name: String) -> ScriptInterpreter {
        shell(name, nextValueFlags: ["o", "O"], valueOptions: ["--rcfile", "--init-file"])
    }

    /// A C shell, which runs the argument after the cluster that holds `-c` as code. `-t` runs one line of standard
    /// input. `-e` exits on an error: it isn't code. `-b` ends the options after its cluster. A lone "-" is a file's
    /// name.
    ///
    /// - Parameter name: The shell's name.
    /// - Returns: The shell.
    private static func cShell(_ name: String) -> ScriptInterpreter {
        ScriptInterpreter(name: name, code: CodeOptions(flags: ["c"], form: .nextArgument, language: .shell),
                          noScriptFlags: ["s", "t"], endFlags: ["b"])
    }

    /// The interpreters Mac Monitor looks for a script for, with their options as `man` and `--help` list them on
    /// macOS 27. `sh` isn't one: `/bin/sh` runs the shell `/private/var/select/sh` names (`bash`) in the same process,
    /// so that exec is the one whose script is read.
    static let supported: [ScriptInterpreter] = [
        bash(named: "bash"),
        /// zsh's `-b` ends its options after its cluster, as csh's does.
        shell("zsh", valueFlags: ["o"], valueOptions: ["--emulate"], endFlags: ["b"]),
        shell("dash", nextValueFlags: ["o"]),
        shell("ksh", valueFlags: ["o", "R"]),
        cShell("csh"),
        cShell("tcsh"),
        ScriptInterpreter(name: "python", code: CodeOptions(flags: ["c"], language: .python), noScriptFlags: ["m"],
                          valueFlags: ["W", "X"], valueOptions: ["--check-hash-based-pycs"]),
        ScriptInterpreter(name: "perl", code: CodeOptions(flags: ["e", "E"], form: .lines, language: .perl),
                          noScriptFlags: ["S"], valueFlags: ["I"],
                          attachedValueFlags: ["C", "d", "D", "F", "i", "m", "M", "V", "x"]),
        /// `--backtrace-limit` is a newer Ruby's (3.0 and later), such as Homebrew's.
        ScriptInterpreter(name: "ruby", code: CodeOptions(flags: ["e"], form: .lines, language: .ruby),
                          noScriptFlags: ["S"], valueFlags: ["C", "E", "I", "r"],
                          attachedValueFlags: ["F", "i", "K", "T", "W", "x"],
                          valueOptions: ["--enable", "--disable", "--encoding", "--external-encoding",
                                         "--internal-encoding", "--dump", "--backtrace-limit"]),
        /// osascript's `-l` names one of the OSA languages `osalang -L` lists. Only AppleScript and JavaScript have
        /// their own colors here, and any other name leaves the code as AppleScript.
        ScriptInterpreter(name: "osascript",
                          code: CodeOptions(flags: ["e"], form: .lines, language: .applescript, languageFlag: "l",
                                            languageNames: ["AppleScript": .applescript, "JavaScript": .javascript]),
                          valueFlags: ["s"]),
        /// Node reads `-pe` as `--print --eval`, and no other cluster: `-e` or `-p` in another means no script and no
        /// code.
        ScriptInterpreter(name: "node",
                          code: CodeOptions(options: ["-e", "-p", "-pe", "--eval", "--print"], form: .last,
                                            language: .javascript),
                          noScriptFlags: ["e", "p"], valueFlags: ["r", "C"], noScriptOptions: ["--run"],
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

    /// `sh`, which is bash on macOS. Its code on the command line is read, though its script isn't (``supported``).
    /// Each exec shows the code it got.
    static let sh = bash(named: "sh")

    /// The interpreter an executable is, for reading the code on its command line: one of ``supported``, or ``sh``.
    ///
    /// - Parameter executableName: The executable's file name.
    /// - Returns: The interpreter, or `nil` when it isn't one.
    static func takingCode(named executableName: String) -> ScriptInterpreter? {
        executableName == sh.name ? sh : named(executableName)
    }
}


// MARK: - Finding the script argument
extension ScriptInterpreter {
    /// The argument that names the script, as the interpreter reads its arguments (``ArgumentReader``): the first
    /// operand that isn't one of its ``subcommands``.
    ///
    /// - Parameter arguments: The arguments after the executable's own (`argv[0]`).
    /// - Returns: The argument as written, or `nil` when the script isn't a file named there: code on the command line,
    ///   standard input (`-`, except to a shell), or no argument at all.
    func scriptArgument<Arguments: Collection>(in arguments: Arguments) -> String? where Arguments.Element == String {
        var reader = ArgumentReader(arguments, for: self)
        var subcommands = self.subcommands
        while let argument = reader.next() {
            switch argument {
            case .operand(let operand):
                if subcommands.remove(operand) == nil { return operand }
            case .endOfOptions:
                if otherOptionsMeanNoScript { return nil }
                /// What follows is the script, whatever it's named.
                subcommands = []
            case .standardInput:
                return nil
            case .option(let option, _):
                if code?.options.contains(option) == true || noScriptOptions.contains(option)
                    || (otherOptionsMeanNoScript && !valueOptions.contains(option)) { return nil }
            case .flag(let flag, let value):
                if otherOptionsMeanNoScript || noScriptFlags.contains(flag) || code?.flags.contains(flag) == true {
                    return nil
                }
                if scriptFlags.contains(flag) { return value }
            }
        }
        return nil
    }
}
