//
//  ScriptInterpreter+Arguments.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/26/26.
//

import Foundation


// MARK: - Arguments
extension ScriptInterpreter {
    /// One of an interpreter's arguments as it reads them: an option, with its value when it takes one, or an operand.
    enum Argument {
        /// "--", or a lone "-" to a shell. Every argument after it is an operand.
        case endOfOptions
        /// A lone "-" that isn't the end of the options: standard input.
        case standardInput
        /// A whole option (`--rcfile`, `--eval`, swift's `-module-name`), with its value when it takes one: after "="
        /// (`--eval=code`), or else the next argument.
        case option(String, value: String?)
        /// A short option, alone or in a cluster (`-c`, or `l` in `-lc`), with its value when it takes one.
        case flag(Character, value: String?)
        /// An argument that isn't an option or an option's value.
        case operand(String)
    }

    /// How a short option takes its value.
    private enum FlagValue {
        /// It takes none.
        case none
        /// The rest of its argument, or else the next argument (`-Wignore`, `-W ignore`).
        case restOrNext
        /// The rest of its argument, when there's any (`perl -i.bak`).
        case rest
        /// The next argument, while the rest of its argument is more options (`bash -oc pipefail code`).
        case next
    }

    /// How one of the interpreter's short options takes its value, from its tables.
    ///
    /// - Parameter flag: The option.
    /// - Returns: How it takes its value.
    private func value(of flag: Character) -> FlagValue {
        if nextValueFlags.contains(flag) { return .next }
        if attachedValueFlags.contains(flag) { return .rest }
        if valueFlags.contains(flag) || scriptFlags.contains(flag) || flag == code?.languageFlag { return .restOrNext }
        guard let code, code.flags.contains(flag) else { return .none }
        switch code.form {
        case .operand: return .none
        case .nextArgument: return .next
        case .value, .lines, .last: return .restOrNext
        }
    }
}


// MARK: - Reading the arguments
extension ScriptInterpreter {
    /// Reads an interpreter's arguments as it does, one option, option value or operand at a time. An option's value
    /// is never read as an option, a cluster (`-lc`) is read one short option at a time, and every argument after the
    /// options end is an operand. The script search (``scriptArgument(in:)``) and the inline code
    /// (``inlineCode(in:executableName:)``) both read them this way.
    struct ArgumentReader<Arguments: Collection>: IteratorProtocol where Arguments.Element == String {
        /// The interpreter that reads the arguments.
        private let interpreter: ScriptInterpreter
        /// The arguments not read yet.
        private var remaining: Arguments.SubSequence
        /// The short options of a cluster not read yet.
        private var cluster: Substring = ""
        /// Have the options ended, at "--" or an ``ScriptInterpreter/endFlags`` option?
        private var optionsEnded = false

        /// A reader of an interpreter's arguments.
        ///
        /// - Parameters:
        ///   - arguments: The arguments after the executable's own (`argv[0]`).
        ///   - interpreter: The interpreter that reads them.
        init(_ arguments: Arguments, for interpreter: ScriptInterpreter) {
            self.interpreter = interpreter
            remaining = arguments[...]
        }

        /// The next option, option value or operand.
        ///
        /// - Returns: The argument, or `nil` after the last.
        mutating func next() -> Argument? {
            if let flag = cluster.popFirst() { return read(flag) }
            guard let argument = remaining.popFirst() else { return nil }
            if optionsEnded { return .operand(argument) }
            if argument == "--" || (interpreter.dashEndsOptions && argument == "-") {
                optionsEnded = true
                return .endOfOptions
            }
            if argument == "-" { return .standardInput }
            if let option = Self.option(argument, in: interpreter.code?.options ?? [])
                ?? Self.option(argument, in: interpreter.noScriptOptions) {
                let value = argument == option ? remaining.popFirst() : String(argument.dropFirst(option.count + 1))
                return .option(option, value: value)
            }
            if interpreter.valueOptions.contains(argument) { return .option(argument, value: remaining.popFirst()) }
            let isOption = argument.count > 1
                && (argument.hasPrefix("-") || (interpreter.plusOptions && argument.hasPrefix("+")))
            guard isOption else { return .operand(argument) }
            guard interpreter.clusters, !argument.hasPrefix("--") else { return .option(argument, value: nil) }
            cluster = argument.dropFirst()
            return read(cluster.removeFirst())
        }

        /// Read a short option of the cluster, and its value when it takes one. A value that's the rest of the
        /// argument ends the cluster (`-Wignore`, `perl -i.e`).
        ///
        /// - Parameter flag: The option.
        /// - Returns: The option, with its value.
        private mutating func read(_ flag: Character) -> Argument {
            if interpreter.endFlags.contains(flag) { optionsEnded = true }
            let kind = interpreter.value(of: flag)
            switch kind {
            case .none: return .flag(flag, value: nil)
            case .next: return .flag(flag, value: remaining.popFirst())
            case .rest, .restOrNext:
                let rest = cluster
                cluster = ""
                if !rest.isEmpty { return .flag(flag, value: String(rest)) }
                return .flag(flag, value: kind == .restOrNext ? remaining.popFirst() : nil)
            }
        }

        /// The whole option an argument is, alone or with its value after "=" (`--eval=code`).
        ///
        /// - Parameters:
        ///   - argument: The argument.
        ///   - options: The whole options it could be.
        /// - Returns: The option, or `nil` when it's none of them.
        private static func option(_ argument: String, in options: Set<String>) -> String? {
            options.first { argument == $0 || argument.hasPrefix($0 + "=") }
        }
    }
}
