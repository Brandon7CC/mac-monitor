//
//  IndicatorInvocation.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Indicator invocations
/// `macmonitor indicators list|add|edit|import|remove|enable|disable|export`: the Mac's indicator set, which the
/// Security Extension runs on every event it captures, for Mac Monitor and every stream.
public enum IndicatorInvocation: Equatable {
    /// The indicator commands, by what's typed, in the order help lists them. The parser switches over every case
    /// with no default, so a command added here doesn't build until it's parsed.
    public enum Name: String, CaseIterable, Sendable {
        case list, show, add, edit, `import`, remove, enable, disable, export

        /// Every name, as help and usage errors list them: "list, show, add, edit, import, remove, enable, disable
        /// or export".
        static var listed: String {
            let names = allCases.map(\.rawValue)
            return names.dropLast().joined(separator: ", ") + " or " + (names.last ?? "")
        }
    }

    /// Show the set: a table, or the indicator file `export` writes (`--format json`).
    case list(format: IndicatorListFormat = .text)
    /// Show every detail of indicators, each named by its identity or its name.
    case show([String])
    /// Add an indicator of your own.
    case add(name: String, predicate: String, severity: IndicatorSeverity = .medium)
    /// Change one indicator's fields, keeping its identity.
    case edit(IndicatorEdit)
    /// Add a file's indicators to the set, or make the set exactly them (`--replace`). `-` reads standard input.
    /// Asks first unless `confirmed` (`--yes`).
    case importFile(path: String, replace: Bool, confirmed: Bool = false)
    /// Remove indicators, each by its identity or its name.
    case remove([String])
    /// Turn indicators on, each by its identity or its name.
    case enable([String])
    /// Turn indicators off, each by its identity or its name.
    case disable([String])
    /// Write the set, or only the indicators named, each by its identity or its name, as an indicator file to
    /// standard output.
    case export(_ references: [String] = [])
}


/// How `macmonitor indicators list` shows the set.
public enum IndicatorListFormat: String, CaseIterable, Sendable {
    /// A table, one indicator a line (``IndicatorTable``).
    case text
    /// The indicator file `macmonitor indicators export` writes, for scripts.
    case json
}


// MARK: - Parsing
extension CommandLineParser {
    /// `indicators <subcommand> ...`.
    ///
    /// - Parameter cursor: The arguments after `indicators`.
    /// - Returns: The indicator command asked for.
    /// - Throws: ``CommandLineUsageError``.
    static func indicators(_ cursor: inout ArgumentCursor) throws -> IndicatorInvocation {
        guard case .positional(let subcommand)? = cursor.next() else {
            throw CommandLineUsageError("indicators needs one of \(IndicatorInvocation.Name.listed).",
                                        command: "indicators")
        }
        guard let name = IndicatorInvocation.Name(rawValue: subcommand) else {
            let names = IndicatorInvocation.Name.allCases.map(\.rawValue)
            let suggestion = CommandLineSuggestion.didYouMean(subcommand, among: names)
            throw CommandLineUsageError("Unknown indicators command '\(subcommand)'.\(suggestion)",
                                        command: "indicators")
        }
        /// Every command, and no default: a new one doesn't build until it's parsed here.
        switch name {
        case .list: return .list(format: try indicatorListFormat(&cursor))
        case .show: return .show(try indicatorReferences(&cursor, subcommand: name))
        case .export: return .export(try indicatorReferences(&cursor, subcommand: name, required: false))
        case .add: return try indicatorAdd(&cursor)
        case .edit: return try indicatorEdit(&cursor)
        case .import: return try indicatorImport(&cursor)
        case .remove: return .remove(try indicatorReferences(&cursor, subcommand: name))
        case .enable: return .enable(try indicatorReferences(&cursor, subcommand: name))
        case .disable: return .disable(try indicatorReferences(&cursor, subcommand: name))
        }
    }

    /// `list [--format text|json] [--json]`. `--json` is short for `--format json`.
    ///
    /// - Parameter cursor: The arguments.
    /// - Returns: The format: text unless given.
    /// - Throws: ``CommandLineUsageError`` for a positional, an unknown format, or an unknown option.
    static func indicatorListFormat(_ cursor: inout ArgumentCursor) throws -> IndicatorListFormat {
        var format = IndicatorListFormat.text
        while let argument = cursor.next() {
            switch argument {
            case .option("--format", let attached):
                let value = try cursor.value(of: "--format", attached: attached, command: "indicators")
                guard let named = IndicatorListFormat(rawValue: value) else {
                    throw CommandLineUsageError("--format must be text or json, not '\(value)'.",
                                                command: "indicators")
                }
                format = named
            case .option("--json", nil):
                format = .json
            case .option("--json", .some):
                throw CommandLineUsageError("--json takes no value.", command: "indicators")
            case .option(let option, _):
                throw unknownOption(option, for: "indicators list", among: CommandLineOption.indicators(.list))
            case .positional(let value):
                throw CommandLineUsageError("indicators list takes no arguments, not '\(value)'.",
                                            command: "indicators")
            }
        }
        return format
    }

    /// `add --name NAME --predicate PREDICATE [--severity low|medium|high]`.
    ///
    /// The predicate is compiled here as the Security Extension compiles it, so one it can't run is refused at once.
    /// The Security Extension's own check is the one that counts.
    ///
    /// - Parameter cursor: The arguments.
    /// - Returns: The indicator to add: medium unless a severity is given.
    /// - Throws: ``CommandLineUsageError``: 64 for a missing or repeated option, a positional, or an unknown option;
    ///   65 for a name that's too long, an unknown severity, or a predicate the Security Extension can't run.
    static func indicatorAdd(_ cursor: inout ArgumentCursor) throws -> IndicatorInvocation {
        var given: [String: String] = [:]
        while let argument = cursor.next() {
            switch argument {
            case .option(let option, let attached) where ["--name", "--predicate", "--severity"].contains(option):
                guard given[option] == nil else {
                    throw CommandLineUsageError("Give \(option) once.", command: "indicators")
                }
                given[option] = try cursor.value(of: option, attached: attached, command: "indicators")
            case .option(let option, _):
                throw unknownOption(option, for: "indicators add", among: CommandLineOption.indicators(.add))
            case .positional(let value):
                throw CommandLineUsageError("indicators add takes --name and --predicate, not '\(value)'.",
                                            command: "indicators")
            }
        }
        guard let name = given["--name"]?.trimmingCharacters(in: .whitespaces), !name.isEmpty else {
            throw CommandLineUsageError("indicators add needs --name NAME.", command: "indicators")
        }
        guard let predicate = given["--predicate"] else {
            throw CommandLineUsageError("indicators add needs --predicate PREDICATE.", command: "indicators")
        }
        guard name.unicodeScalars.count <= Indicator.Limits.name else {
            throw CommandLineUsageError.unusableIndicator(
                "The name is longer than \(Indicator.Limits.name) characters.")
        }
        let severity = try given["--severity"].map(indicatorSeverity) ?? .medium
        if let problem = IndicatorCompiler.problem(with: predicate) {
            throw CommandLineUsageError.unusableIndicator("The Security Extension can't run the predicate. \(problem)")
        }
        return .add(name: name, predicate: predicate, severity: severity)
    }

    /// A `--severity` value.
    ///
    /// - Parameter value: What was typed, in any case.
    /// - Returns: The severity.
    /// - Throws: ``CommandLineUsageError/unusableIndicator(_:)`` for anything but low, medium or high.
    static func indicatorSeverity(_ value: String) throws -> IndicatorSeverity {
        guard let severity = IndicatorSeverity(rawValue: value.lowercased()) else {
            let names = IndicatorSeverity.allCases.map(\.rawValue)
            throw CommandLineUsageError.unusableIndicator("""
                --severity must be \(names.dropLast().joined(separator: ", ")) or \(names.last ?? ""), not \
                '\(value)'.
                """)
        }
        return severity
    }

    /// `import FILE|- [--replace] [--yes]`.
    ///
    /// - Parameter cursor: The arguments.
    /// - Returns: The import.
    /// - Throws: ``CommandLineUsageError`` for no file or more than one, a value given to `--replace` or `--yes`, or
    ///   an unknown option.
    static func indicatorImport(_ cursor: inout ArgumentCursor) throws -> IndicatorInvocation {
        let (path, flags) = try cursor.flags(of: "indicators import", among: CommandLineOption.indicators(.import),
                                             positional: "file", command: "indicators")
        guard let path else {
            throw CommandLineUsageError("indicators import needs a file, or - for standard input.",
                                        command: "indicators")
        }
        return .importFile(path: path, replace: flags.contains("--replace"), confirmed: flags.contains("--yes"))
    }

    /// `ID|NAME...`: the indicators `remove`, `enable`, `disable` and `export` act on. `--` ends the options, for a
    /// name that starts with `-`.
    ///
    /// - Parameters:
    ///   - cursor: The arguments.
    ///   - subcommand: The command, for messages.
    ///   - required: Is one needed? `export` with none writes the whole set.
    /// - Returns: Each identity or name, as typed, in order.
    /// - Throws: ``CommandLineUsageError`` for none when one is required, an empty one, or any option.
    static func indicatorReferences(_ cursor: inout ArgumentCursor, subcommand: IndicatorInvocation.Name,
                                    required: Bool = true) throws -> [String] {
        var references: [String] = []
        while let argument = cursor.next() {
            switch argument {
            case .positional(let value) where !value.trimmingCharacters(in: .whitespaces).isEmpty:
                references.append(value)
            case .positional:
                throw CommandLineUsageError("An indicator's name can't be empty.", command: "indicators")
            case .option(let option, _):
                throw unknownOption(option, for: "indicators \(subcommand.rawValue)", among: [])
            }
        }
        guard !references.isEmpty || !required else {
            throw CommandLineUsageError("indicators \(subcommand.rawValue) needs an indicator's ID or name.",
                                        command: "indicators")
        }
        return references
    }
}


// MARK: - Usage errors
extension CommandLineUsageError {
    /// An indicator on the command line that can't be used, such as one whose predicate the Security Extension can't
    /// run. It exits 65, as an indicator the Security Extension refuses does.
    ///
    /// - Parameter message: What's wrong with it.
    /// - Returns: The error, pointing to `indicators`'s help.
    static func unusableIndicator(_ message: String) -> CommandLineUsageError {
        CommandLineUsageError(message, command: "indicators", exit: .dataError)
    }
}
