//
//  IndicatorInvocation.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Indicator invocations
/// `macmonitor indicators list|add|edit|import|remove|enable|disable|export`: the Mac's indicator set, which the
/// Security Extension runs on every event it captures, for Mac Monitor and every stream. And `indicators test`, which
/// tests an indicator pack on recorded events without the Security Extension, and `indicators pack`, its signed
/// releases.
public enum IndicatorInvocation: Equatable {
    /// The indicator commands, by what's typed, in the order help lists them. The parser switches over every case
    /// with no default, so a command added here doesn't build until it's parsed.
    public enum Name: String, CaseIterable, Sendable {
        case list, show, add, edit, `import`, remove, enable, disable, export, test, pack

        /// Every name, as help and usage errors list them: "list, show, add, edit, import, remove, enable, disable,
        /// export, test or pack".
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
    /// Test an indicator pack's payload on the recorded events a plan names, with the Security Extension's code but
    /// without it (``IndicatorTestRun``).
    case test(pack: String, plan: String)
    /// A signed indicator pack.
    case pack(IndicatorPackInvocation)

    /// Does it talk to the Security Extension? Every command does but `test` and `pack verify`.
    public var needsSecurityExtension: Bool {
        switch self {
        case .test, .pack(.verify): return false
        default: return true
        }
    }
}


/// `macmonitor indicators pack status|check|install|mode|verify`: a signed indicator pack, as the indicators
/// repository releases one.
public enum IndicatorPackInvocation: Equatable {
    /// The pack commands, by what's typed, in the order help lists them.
    public enum Name: String, CaseIterable, Sendable {
        case status, check, install, mode, verify

        /// The commands this build has: without those that ask GitHub while pack updates wait for a later release
        /// (``IndicatorPackUpdates/isAvailable``).
        public static var offered: [Name] {
            IndicatorPackUpdates.isAvailable ? allCases : [.status, .install, .verify]
        }
    }

    /// Show which pack Mac Monitor's own indicators are, the update mode, and what the last look for a newer pack
    /// found. Nothing is asked of GitHub.
    case status(json: Bool = false)
    /// Have the Security Extension look on GitHub for a newer pack, and say what installing it would change.
    case check(json: Bool = false)
    /// Have the Security Extension install a signed pack as Mac Monitor's own indicators: a file's, `-` for standard
    /// input, or with no path the newest on GitHub. Asks first unless `confirmed` (`--yes`).
    case install(path: String?, confirmed: Bool = false)
    /// Set what the Security Extension does about newer packs.
    case mode(IndicatorPackMode)
    /// Check a signed pack file as the Security Extension checks one before installing it, and say what it holds
    /// (``IndicatorPackVerifyCommand``).
    case verify(String)
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
        case .test: return try indicatorTest(&cursor)
        case .pack: return .pack(try indicatorPack(&cursor))
        }
    }

    /// `pack status [--json]`, `pack check [--json]`, `pack install [FILE|-] [--yes]`, `pack mode off|notify|auto`
    /// or `pack verify FILE`.
    ///
    /// - Parameter cursor: The arguments after `pack`.
    /// - Returns: The pack command asked for.
    /// - Throws: ``CommandLineUsageError`` (64) for a missing or unknown command, a missing or second file, or an
    ///   option the command doesn't take.
    static func indicatorPack(_ cursor: inout ArgumentCursor) throws -> IndicatorPackInvocation {
        let names = IndicatorPackInvocation.Name.offered.map(\.rawValue)
        guard case .positional(let subcommand)? = cursor.next() else {
            let listed = names.dropLast().joined(separator: ", ") + " or " + (names.last ?? "")
            throw CommandLineUsageError("indicators pack needs \(listed).", command: "indicators")
        }
        guard let name = IndicatorPackInvocation.Name(rawValue: subcommand),
              IndicatorPackInvocation.Name.offered.contains(name) else {
            let suggestion = CommandLineSuggestion.didYouMean(subcommand, among: names)
            throw CommandLineUsageError("Unknown indicators pack command '\(subcommand)'.\(suggestion)",
                                        command: "indicators")
        }
        switch name {
        case .verify:
            var file: String?
            while let argument = cursor.next() {
                switch argument {
                case .option(let option, _):
                    throw unknownOption(option, for: "indicators pack verify", among: [])
                case .positional(let value):
                    guard file == nil else {
                        throw CommandLineUsageError("indicators pack verify takes one file, not '\(value)' too.",
                                                    command: "indicators")
                    }
                    file = value
                }
            }
            guard let file else {
                throw CommandLineUsageError("indicators pack verify needs a pack file.", command: "indicators")
            }
            return .verify(file)
        case .install:
            let (path, flags) = try cursor.flags(of: "indicators pack install", among: [CommandLineOption("--yes")],
                                                 positional: "file", command: "indicators")
            guard path != nil || IndicatorPackUpdates.isAvailable else {
                throw CommandLineUsageError("indicators pack install needs a pack file.", command: "indicators")
            }
            return .install(path: path, confirmed: flags.contains("--yes"))
        case .status, .check:
            let (_, flags) = try cursor.flags(of: "indicators pack \(subcommand)",
                                              among: [CommandLineOption("--json")], positional: nil,
                                              command: "indicators")
            return name == .status ? .status(json: flags.contains("--json")) : .check(json: flags.contains("--json"))
        case .mode:
            let modes = IndicatorPackMode.allCases.map(\.rawValue)
            let (typed, _) = try cursor.flags(of: "indicators pack mode", among: [], positional: "mode",
                                              command: "indicators")
            guard let typed, let mode = IndicatorPackMode(rawValue: typed) else {
                throw CommandLineUsageError("indicators pack mode needs \(modes.joined(separator: ", ")).",
                                            command: "indicators")
            }
            return .mode(mode)
        }
    }

    /// `test PACK --plan PLAN`.
    ///
    /// - Parameter cursor: The arguments.
    /// - Returns: The pack's payload and the plan, by path.
    /// - Throws: ``CommandLineUsageError`` (64) for a missing or repeated pack or plan, or an unknown option.
    static func indicatorTest(_ cursor: inout ArgumentCursor) throws -> IndicatorInvocation {
        var pack: String?, plan: String?
        while let argument = cursor.next() {
            switch argument {
            case .option("--plan", let attached):
                guard plan == nil else { throw CommandLineUsageError("Give --plan once.", command: "indicators") }
                plan = try cursor.value(of: "--plan", attached: attached, command: "indicators")
            case .option(let option, _):
                throw unknownOption(option, for: "indicators test", among: CommandLineOption.indicators(.test))
            case .positional(let value):
                guard pack == nil else {
                    throw CommandLineUsageError("indicators test takes one pack, not '\(value)' too.",
                                                command: "indicators")
                }
                pack = value
            }
        }
        guard let pack, let plan else {
            throw CommandLineUsageError("indicators test needs a pack and --plan PLAN.", command: "indicators")
        }
        return .test(pack: pack, plan: plan)
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
    /// - Throws: ``CommandLineUsageError``: 64 for a missing or repeated option, a positional, or an unknown option.
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
