//
//  ScriptInterpreter+InlineCode.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/26/26.
//

import Foundation


// MARK: - Code options
extension ScriptInterpreter {
    /// How an interpreter takes code on its command line.
    struct CodeOptions {
        /// Short options that give code, alone or in a cluster (`-c`, `-lc`).
        var flags: Set<Character> = []
        /// Whole options whose value is code: the next argument, or after "=" (`--eval code`, `--eval=code`).
        var options: Set<String> = []
        /// Where the code is, and how several pieces combine.
        var form: CodeForm = .value
        /// The code's language.
        let language: InlineCode.Language
        /// The short option whose value names the code's language (`osascript -l JavaScript`). The last one wins.
        var languageFlag: Character? = nil
        /// The languages ``languageFlag`` names, by the name it takes for each. Another name leaves the language as
        /// it was: osascript refuses most ("no such component"), and runs the rest as its default language.
        var languageNames: [String: InlineCode.Language] = [:]
    }

    /// Where an interpreter's code is, and how several pieces combine.
    enum CodeForm {
        /// The option's value: the rest of its argument, or else the next argument. It ends the options, and what
        /// follows is the code's arguments (`python3 -c`).
        case value
        /// The option's value, as for ``value``. Every one is a line of the code, joined in order, and options
        /// continue until the first other argument (`osascript -e a -e b`, `perl -e`, `ruby -e`).
        case lines
        /// The option's value, as for ``value``. A later one replaces it (`node -e`).
        case last
        /// The first argument that isn't an option or an option's value, wherever the option is among them
        /// (`bash -c -x code`, a Bourne-style shell's command string).
        case operand
        /// The next argument, whatever it is, while the rest of the option's argument is more options
        /// (`tcsh -c -x` runs `-x`, and `tcsh -cf 'echo hi'` runs `echo hi`).
        case nextArgument

        /// Is the code a shell's command string? A shell runs it whatever else its options say: `bash -s -c code`
        /// runs the code, and dash reads standard input after it.
        var isCommandString: Bool { self == .operand || self == .nextArgument }
    }
}


// MARK: - Reading the code
extension ScriptInterpreter {
    /// The code the interpreter got on its command line, read as the interpreter reads its arguments
    /// (``ArgumentReader``): its options until the first operand.
    ///
    /// - Parameters:
    ///   - arguments: The arguments after the executable's own (`argv[0]`).
    ///   - executableName: The executable's file name, for ``InlineCode/interpreter``.
    /// - Returns: The code, or `nil` when the interpreter's code isn't read, or the arguments give none or only white
    ///   space, such as a script file's (`python3 tool.py`).
    func inlineCode<Arguments: Collection>(in arguments: Arguments, executableName: String) -> InlineCode?
    where Arguments.Element == String {
        guard let code else { return nil }
        var reader = ArgumentReader(arguments, for: self)
        var pieces: [(option: String, text: String)] = []
        var language = code.language
        /// The option that makes the first operand the code (`bash -c`), once it's seen.
        var operandOption: String?

        /// Keep a piece of code.
        ///
        /// - Parameters:
        ///   - text: The piece, or `nil` when the option has no value.
        ///   - option: The option that gave it.
        /// - Returns: Does the interpreter read no more options after it?
        func keep(_ text: String?, from option: String) -> Bool {
            guard let text else { return true }
            if code.form == .lines { pieces.append((option, text)) } else { pieces = [(option, text)] }
            return code.form != .lines && code.form != .last
        }

        reading: while let argument = reader.next() {
            switch argument {
            case .operand(let operand):
                if let operandOption { _ = keep(operand, from: operandOption) }
                break reading
            case .standardInput:
                break reading
            case .endOfOptions:
                continue
            case .option(let option, let value):
                if code.options.contains(option) {
                    if keep(value, from: option) { break reading }
                } else if noScriptOptions.contains(option) {
                    break reading
                }
            case .flag(let flag, let value):
                if code.flags.contains(flag) {
                    if code.form == .operand {
                        operandOption = "-\(flag)"
                    } else if keep(value, from: "-\(flag)") {
                        break reading
                    }
                } else if flag == code.languageFlag {
                    language = value.flatMap { code.languageNames[$0] } ?? language
                } else if noScriptFlags.contains(flag), !code.form.isCommandString {
                    break reading
                }
            }
        }
        let text = pieces.map(\.text).joined(separator: "\n")
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
        return InlineCode(interpreter: executableName, text: text, options: pieces.map(\.option), language: language)
    }
}
