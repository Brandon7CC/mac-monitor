//
//  IndicatorEdit.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - An edit
/// `macmonitor indicators edit ID|NAME ...`: one indicator, and what to change of it. It keeps the indicator's
/// identity, and never turns it on or off nor changes how anyone's tables mark it.
public struct IndicatorEdit: Equatable {
    /// Where the new values come from.
    public enum Change: Equatable {
        /// The options typed, each field's value checked and in its canonical form: a tactic's raw value, a
        /// technique in capitals, a severity's raw value, and `""` for a tactic or technique of none.
        case values([Indicator.EditableField: String])
        /// The editable keys one indicator in a file has, or standard input for `-`. Asks first unless `confirmed`.
        case file(String, confirmed: Bool)
        /// Every editable field as this build ships the indicator.
        case restore
    }

    /// The indicator's identity or name, as typed.
    public let reference: String
    /// What to change.
    public let change: Change

    /// - Parameters:
    ///   - reference: The indicator's identity or name, as typed.
    ///   - change: What to change.
    public init(_ reference: String, _ change: Change) {
        self.reference = reference
        self.change = change
    }

    /// The options that each set one field, in the order help lists them.
    static let fieldOptions: [(option: String, field: Indicator.EditableField)] = [
        ("--name", .name), ("--predicate", .predicate), ("--severity", .severity), ("--description", .description),
        ("--tactic", .tactic), ("--technique", .technique), ("--symbol", .symbol),
    ]

    /// An indicator with the typed values in place of its own.
    ///
    /// - Parameters:
    ///   - values: The values, as ``Change/values(_:)`` holds them.
    ///   - target: The indicator.
    /// - Returns: It, edited.
    static func applying(_ values: [Indicator.EditableField: String], to target: Indicator) -> Indicator {
        var edited = target
        for (field, value) in values {
            switch field {
            case .name: edited.name = value
            case .description: edited.description = value
            case .symbol: edited.symbol = value
            case .predicate: edited.predicate = value
            case .tactic: edited.tactic = Indicator.Tactic(rawValue: value)
            case .technique: edited.technique = value.isEmpty ? nil : value
            case .severity: edited.severity = IndicatorSeverity(rawValue: value) ?? edited.severity
            case .color: continue
            }
        }
        return edited
    }
}


// MARK: - Parsing
extension CommandLineParser {
    /// `edit ID|NAME [--name NAME] [--predicate P] [--severity S] [--description T] [--tactic T|none]
    /// [--technique ID|none] [--symbol NAME]`, or `edit ID|NAME --file FILE|- [--yes]`, or `edit ID|NAME --restore`.
    ///
    /// Each value is checked here as the Security Extension checks it, so one it would refuse exits at once.
    ///
    /// - Parameter cursor: The arguments.
    /// - Returns: The edit.
    /// - Throws: ``CommandLineUsageError``: 64 for no indicator or more than one, an option given twice or without its
    ///   value, an unknown option, nothing to change, or options that don't go together, and 65 for a value that
    ///   can't be used.
    static func indicatorEdit(_ cursor: inout ArgumentCursor) throws -> IndicatorInvocation {
        var references: [String] = [], given: [String: String] = [:], flags = Set<String>()
        let valued = Set(IndicatorEdit.fieldOptions.map(\.option) + ["--file"])
        while let argument = cursor.next() {
            switch argument {
            case .positional(let value) where value.trimmingCharacters(in: .whitespaces).isEmpty:
                throw CommandLineUsageError("An indicator's name can't be empty.", command: "indicators")
            case .positional(let value):
                references.append(value)
            case .option(let option, let attached) where valued.contains(option):
                guard given[option] == nil else { throw once(option) }
                given[option] = try cursor.value(of: option, attached: attached, command: "indicators")
            case .option(let option, let attached) where ["--yes", "--restore"].contains(option):
                guard attached == nil else {
                    throw CommandLineUsageError("\(option) takes no value.", command: "indicators")
                }
                guard flags.insert(option).inserted else { throw once(option) }
            case .option(let option, _):
                throw unknownOption(option, for: "indicators edit", among: CommandLineOption.indicators(.edit))
            }
        }
        guard let reference = references.first else {
            throw CommandLineUsageError("indicators edit needs an indicator's ID or name.", command: "indicators")
        }
        guard references.count == 1 else {
            throw CommandLineUsageError("indicators edit takes one indicator's ID or name.", command: "indicators")
        }
        return .edit(IndicatorEdit(reference, try editChange(given, flags: flags)))
    }

    /// What an edit changes, from its options.
    ///
    /// - Parameters:
    ///   - given: Each option given with its value.
    ///   - flags: `--yes` and `--restore`, if given.
    /// - Returns: The change.
    /// - Throws: ``CommandLineUsageError``: 64 for nothing to change or options that don't go together, 65 for a
    ///   value that can't be used.
    private static func editChange(_ given: [String: String], flags: Set<String>) throws -> IndicatorEdit.Change {
        let fields = IndicatorEdit.fieldOptions.filter { given[$0.option] != nil }
        let file = given["--file"], restore = flags.contains("--restore")
        guard [!fields.isEmpty, file != nil, restore].filter({ $0 }).count == 1 else {
            let options = (IndicatorEdit.fieldOptions.map(\.option) + ["--file"]).joined(separator: ", ")
            let message = fields.isEmpty && file == nil && !restore
                ? "indicators edit needs at least one of \(options) or --restore."
                : "indicators edit takes field options, --file or --restore: one of them, not more."
            throw CommandLineUsageError(message, command: "indicators")
        }
        guard file != nil || !flags.contains("--yes") else {
            throw CommandLineUsageError("--yes goes with --file: only an edit from a file asks first.",
                                        command: "indicators")
        }
        if let file { return .file(file, confirmed: flags.contains("--yes")) }
        if restore { return .restore }
        var values: [Indicator.EditableField: String] = [:]
        for (option, field) in fields {
            values[field] = try editValue(given[option] ?? "", for: field)
        }
        return .values(values)
    }

    /// One field's value, checked and in its canonical form.
    ///
    /// - Parameters:
    ///   - value: What was typed.
    ///   - field: The field.
    /// - Returns: The value as ``IndicatorEdit/Change/values(_:)`` holds it.
    /// - Throws: ``CommandLineUsageError/unusableIndicator(_:)`` for a value the Security Extension would refuse.
    private static func editValue(_ value: String, for field: Indicator.EditableField) throws -> String {
        let none = value.caseInsensitiveCompare("none") == .orderedSame
        switch field {
        case .name:
            let name = value.trimmingCharacters(in: .whitespaces)
            guard !name.isEmpty else { throw CommandLineUsageError.unusableIndicator("The name can't be empty.") }
            guard name.unicodeScalars.count <= Indicator.Limits.name else {
                throw CommandLineUsageError.unusableIndicator(
                    "The name is longer than \(Indicator.Limits.name) characters.")
            }
            return name
        case .predicate:
            if let problem = IndicatorCompiler.problem(with: value) {
                throw CommandLineUsageError.unusableIndicator(
                    "The Security Extension can't run the predicate. \(problem)")
            }
            return value
        case .severity:
            return try indicatorSeverity(value).rawValue
        case .description:
            guard value.utf8.count <= Indicator.Limits.descriptionBytes else {
                throw CommandLineUsageError.unusableIndicator(
                    "The description is longer than \(Indicator.Limits.descriptionBytes / 1_024) KiB.")
            }
            return value
        case .tactic:
            if none { return "" }
            guard let tactic = Indicator.Tactic.named(value) else {
                let names = Indicator.Tactic.allCases.map(\.rawValue).joined(separator: ", ")
                throw CommandLineUsageError.unusableIndicator("""
                    --tactic must be one of \(names), its ATT&CK ID or name, or none, not '\(value)'.
                    """)
            }
            return tactic.rawValue
        case .technique:
            if none { return "" }
            let technique = value.uppercased()
            guard Indicator.isTechnique(technique) else {
                throw CommandLineUsageError.unusableIndicator("""
                    --technique must be an ATT&CK technique, such as T1059 or T1059.002, or none, not '\(value)'.
                    """)
            }
            return technique
        case .symbol:
            guard !value.isEmpty, value.unicodeScalars.count <= Indicator.Limits.symbol else {
                throw CommandLineUsageError.unusableIndicator(
                    "The symbol's name must be 1 to \(Indicator.Limits.symbol) characters.")
            }
            return value
        case .color:
            return value
        }
    }

    /// - Parameter option: An option given twice.
    /// - Returns: The usage error.
    private static func once(_ option: String) -> CommandLineUsageError {
        CommandLineUsageError("Give \(option) once.", command: "indicators")
    }
}
