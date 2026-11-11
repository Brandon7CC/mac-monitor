//
//  IndicatorEditCommandLineTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - indicators edit's command line
/// Pins `macmonitor indicators edit`'s command line: one indicator, each field option checked as the Security
/// Extension would check it and kept in its canonical form, `--file` with `--yes`, `--restore`, and a usage error that
/// says what's wrong for everything else: 64 for a command line that can't be read, 65 for a value that can't be used.
final class IndicatorEditCommandLineTests: XCTestCase {
    /// Parse an `indicators edit` command line.
    ///
    /// - Parameter arguments: The arguments after `edit`.
    /// - Returns: The edit, or `nil` when it isn't one.
    /// - Throws: ``CommandLineUsageError``.
    private func parse(_ arguments: String...) throws -> IndicatorEdit? {
        guard case .indicators(.edit(let edit)) = try CommandLineParser.parse(["indicators", "edit"] + arguments)
        else { return nil }
        return edit
    }

    /// The usage error an `indicators edit` command line gets, and how `macmonitor` exits for it.
    ///
    /// - Parameter arguments: The arguments after `edit`.
    /// - Returns: The message and exit status, or `nil` if it parses.
    private func refusal(_ arguments: [String]) -> (message: String, exit: CommandLineExit)? {
        thrown(CommandLineUsageError.self) { try CommandLineParser.parse(["indicators", "edit"] + arguments) }
            .map { ($0.message, CommandLineFailure.parsing($0).exit) }
    }

    /// Each field option, as `--option VALUE` or `--option=VALUE`, in its canonical form: the name trimmed, a
    /// severity in any case, a tactic by any name or none, a technique in any case or none, and an description
    /// that may be empty. `--` before a name that starts with a dash.
    func testEachFieldOption() throws {
        let curl = IndicatorCommandLineTests.curl
        XCTAssertEqual(try parse("Plist modified", "--name", " Plist written ", "--predicate=\(curl)",
                                 "--severity", "HIGH", "--description", "", "--symbol", "doc.badge.gearshape"),
                       IndicatorEdit("Plist modified", .values([.name: "Plist written", .predicate: curl,
                                                                .severity: "high", .description: "",
                                                                .symbol: "doc.badge.gearshape"])))
        let tactics = [("TA0003", "persistence"), ("defense-evasion", "defenseEvasion"),
                       ("Command and Control", "commandAndControl"), ("NONE", "")]
        for (typed, canonical) in tactics {
            XCTAssertEqual(try parse("A", "--tactic", typed), IndicatorEdit("A", .values([.tactic: canonical])), typed)
        }
        XCTAssertEqual(try parse("A", "--technique=t1059.002"), IndicatorEdit("A", .values([.technique: "T1059.002"])))
        XCTAssertEqual(try parse("A", "--technique", "none"), IndicatorEdit("A", .values([.technique: ""])))
        XCTAssertEqual(try parse("--severity", "low", "--", "-odd"), IndicatorEdit("-odd", .values([.severity: "low"])))
    }

    /// `--file FILE|-`, with `--yes` to skip the question, and `--restore`, each alone.
    func testFileAndRestore() throws {
        XCTAssertEqual(try parse("A", "--file", "one.json"), IndicatorEdit("A", .file("one.json", confirmed: false)))
        XCTAssertEqual(try parse("--yes", "--file", "-", "A"), IndicatorEdit("A", .file("-", confirmed: true)))
        XCTAssertEqual(try parse("A", "--restore"), IndicatorEdit("A", .restore))
    }

    /// What can't be read exits 64: no indicator or two, an empty name, nothing to change, an option twice or with
    /// no value, a value given to a flag, options that don't go together, `--yes` without `--file`, and an unknown
    /// option, with a suggestion.
    func testUsageErrors() {
        let refusals: [([String], String)] = [
            (["--severity", "low"], "indicators edit needs an indicator's ID or name."),
            (["A", "B", "--severity", "low"], "indicators edit takes one indicator's ID or name."),
            ([" ", "--severity", "low"], "An indicator's name can't be empty."),
            (["A"], "indicators edit needs at least one of --name, --predicate, --severity, --description, --tactic, "
                + "--technique, --symbol, --file or --restore."),
            (["A", "--name", "B", "--name", "C"], "Give --name once."),
            (["A", "--restore", "--restore"], "Give --restore once."),
            (["A", "--name"], "--name needs a value."),
            (["A", "--restore=yes"], "--restore takes no value."),
            (["A", "--file", "one.json", "--severity", "low"],
             "indicators edit takes field options, --file or --restore: one of them, not more."),
            (["A", "--restore", "--name", "B"],
             "indicators edit takes field options, --file or --restore: one of them, not more."),
            (["A", "--restore", "--file", "one.json"],
             "indicators edit takes field options, --file or --restore: one of them, not more."),
            (["A", "--severity", "low", "--yes"], "--yes goes with --file: only an edit from a file asks first."),
            (["A", "--sevrity", "low"], "Unknown option '--sevrity' for indicators edit. Did you mean '--severity'?"),
            (["A", "--enabled"], "Unknown option '--enabled' for indicators edit."),
        ]
        for (arguments, message) in refusals {
            let refused = refusal(arguments)
            XCTAssertEqual(refused?.message, message, arguments.joined(separator: " "))
            XCTAssertEqual(refused?.exit, .usage, arguments.joined(separator: " "))
        }
    }

    /// A value the Security Extension would refuse exits 65: an empty or long name, a predicate it can't run, an
    /// unknown severity or tactic, a technique that isn't one, a long description, and an empty or long symbol.
    func testUnusableValues() throws {
        let refusals: [([String], String)] = [
            (["--name", "  "], "The name can't be empty."),
            (["--name", String(repeating: "n", count: Indicator.Limits.name + 1)],
             "The name is longer than \(Indicator.Limits.name) characters."),
            (["--predicate", #"process.executable.path ENDSWITH "/curl""#],
             "The Security Extension can't run the predicate. \(SensorProblem.untyped)"),
            (["--severity", "critical"], "--severity must be low, medium or high, not 'critical'."),
            (["--technique", "1059"],
             "--technique must be an ATT&CK technique, such as T1059 or T1059.002, or none, not '1059'."),
            (["--description", String(repeating: "e", count: Indicator.Limits.descriptionBytes + 1)],
             "The description is longer than 2 KiB."),
            (["--symbol", ""], "The symbol's name must be 1 to \(Indicator.Limits.symbol) characters."),
            (["--symbol", String(repeating: "s", count: Indicator.Limits.symbol + 1)],
             "The symbol's name must be 1 to \(Indicator.Limits.symbol) characters."),
        ]
        for (arguments, message) in refusals {
            let refused = refusal(["A"] + arguments)
            XCTAssertEqual(refused?.message, message, arguments.joined(separator: " "))
            XCTAssertEqual(refused?.exit, .dataError, arguments.joined(separator: " "))
        }
        let tactic = try XCTUnwrap(refusal(["A", "--tactic", "stealth"]))
        XCTAssertTrue(tactic.message.hasPrefix("--tactic must be one of reconnaissance, resourceDevelopment, "),
                      tactic.message)
        XCTAssertTrue(tactic.message.hasSuffix(", its ATT&CK ID or name, or none, not 'stealth'."), tactic.message)
        XCTAssertEqual(tactic.exit, .dataError)
    }

    /// The typed values replace the indicator's, the rest stay, and a tactic or technique of none clears it.
    func testValuesApply() throws {
        let original = try XCTUnwrap(Indicator.defaults.first { $0.tactic != nil && $0.technique != nil })
        let edited = IndicatorEdit.applying([.name: "Renamed", .tactic: "", .technique: "", .severity: "high",
                                             .predicate: IndicatorCommandLineTests.curl], to: original)
        XCTAssertEqual(original.changedFields(to: edited).filter { $0 != .severity },
                       [.name, .predicate, .tactic, .technique])
        XCTAssertEqual([edited.name, edited.predicate], ["Renamed", IndicatorCommandLineTests.curl])
        XCTAssertNil(edited.tactic)
        XCTAssertNil(edited.technique)
        XCTAssertEqual(edited.severity, .high)
        XCTAssertEqual(IndicatorEdit.applying([.tactic: "impact", .technique: "T1059"], to: original).tactic, .impact)
    }

    /// `edit` lists every option it parses, `--file` completes a file and `--tactic` and `--severity` their words,
    /// and help shows each.
    func testOptionsCompletionAndHelp() throws {
        let options = CommandLineOption.indicators(.edit)
        XCTAssertEqual(options.map(\.name), ["--name", "--predicate", "--severity", "--description", "--tactic",
                                             "--technique", "--symbol", "--file", "--yes", "--restore"])
        XCTAssertEqual(options.first { $0.name == "--file" }?.value, .file)
        XCTAssertEqual(options.first { $0.name == "--tactic" }?.value,
                       .choice(Indicator.Tactic.allCases.map(\.rawValue) + ["none"]))
        for option in options where option.value != .none {
            let value = option.name == "--file" ? "one.json" : option.name == "--tactic" ? "impact"
                : option.name == "--severity" ? "low" : option.name == "--technique" ? "T1059"
                : option.name == "--predicate" ? IndicatorCommandLineTests.curl : "x"
            XCTAssertNotNil(try parse("A", option.name, value), option.name)
        }
        XCTAssertNotNil(try parse("A", "--restore"))
        XCTAssertNotNil(try parse("A", "--file", "-", "--yes"))
        let script = CommandLineCompletion.script(for: .zsh)
        XCTAssertTrue(script.contains("'indicators edit')"))
        XCTAssertTrue(script.contains("--file) _files; return ;;"))
        XCTAssertTrue(script.contains("--tactic) compadd -- reconnaissance "))
        let help = CommandLineHelp.text(for: "indicators")
        for line in ["  edit ID|NAME [--name NAME]", "  edit ID|NAME --file FILE|- [--yes]", "  edit ID|NAME --restore",
                     "  export [ID|NAME...]"] {
            XCTAssertTrue(help.contains(line), line)
        }
    }
}
