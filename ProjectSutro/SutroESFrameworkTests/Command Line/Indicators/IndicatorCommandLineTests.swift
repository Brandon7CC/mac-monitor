//
//  IndicatorCommandLineTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Indicator command lines
/// Pins `macmonitor indicators`'s command line: every subcommand, medium unless a severity is given, a predicate the
/// Security Extension can run, and a usage error that says what's wrong for everything else: 64 for a command line
/// that can't be read, 65 for an indicator that can't be used, as with `mute`.
final class IndicatorCommandLineTests: XCTestCase {
    /// A predicate the Security Extension runs.
    static let curl = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND process.executable.path ENDSWITH "/curl""#

    /// Parse an indicators command line.
    ///
    /// - Parameter arguments: The arguments after `indicators`.
    /// - Returns: The invocation.
    /// - Throws: ``CommandLineUsageError``.
    private func parse(_ arguments: String...) throws -> CommandLineInvocation {
        try CommandLineParser.parse(["indicators"] + arguments)
    }

    /// The usage error an indicators command line gets.
    ///
    /// - Parameter arguments: The arguments after `indicators`.
    /// - Returns: The error's message, or `nil` if it parses.
    private func usageError(_ arguments: String...) -> String? {
        thrown(CommandLineUsageError.self) { try CommandLineParser.parse(["indicators"] + arguments) }?.message
    }

    /// How `macmonitor` exits for an indicators command line it can't act on.
    ///
    /// - Parameter arguments: The arguments after `indicators`.
    /// - Returns: The exit status, or `nil` if it parses.
    private func exitStatus(_ arguments: [String]) -> CommandLineExit? {
        thrown(Error.self) { try CommandLineParser.parse(["indicators"] + arguments) }
            .map(CommandLineFailure.parsing)?.exit
    }

    /// `list` takes only its format, `--json` for short, and `export` only the indicators to write, none for all.
    /// Every indicators command needs root.
    func testListAndExport() throws {
        XCTAssertEqual(try parse("list"), .indicators(.list(format: .text)))
        XCTAssertEqual(try parse("list", "--format", "json"), .indicators(.list(format: .json)))
        XCTAssertEqual(try parse("list", "--format=text"), .indicators(.list(format: .text)))
        XCTAssertEqual(try parse("list", "--json"), .indicators(.list(format: .json)))
        XCTAssertEqual(try parse("export"), .indicators(.export()))
        XCTAssertEqual(try parse("show", "Plist modified", "New executable"),
                       .indicators(.show(["Plist modified", "New executable"])))
        XCTAssertThrowsError(try parse("show"), "show needs an indicator")
        XCTAssertTrue(try parse("list").requiresRoot)
        XCTAssertEqual(try parse("list").id, .indicators)
        XCTAssertEqual(usageError("list", "all"), "indicators list takes no arguments, not 'all'.")
        XCTAssertEqual(usageError("list", "--format", "jsonl"), "--format must be text or json, not 'jsonl'.")
        XCTAssertEqual(usageError("list", "--json=yes"), "--json takes no value.")
        XCTAssertEqual(usageError("list", "--jsn"),
                       "Unknown option '--jsn' for indicators list. Did you mean '--json'?")
        XCTAssertEqual(try parse("export", "Plist modified", "--", "-odd"),
                       .indicators(.export(["Plist modified", "-odd"])))
        XCTAssertEqual(usageError("export", "--format", "json"), "Unknown option '--format' for indicators export.")
        XCTAssertEqual(usageError("export", " "), "An indicator's name can't be empty.")
        XCTAssertEqual(usageError(),
                       "indicators needs one of list, show, add, edit, import, remove, enable, disable or export.")
        XCTAssertEqual(usageError("lst"), "Unknown indicators command 'lst'. Did you mean 'list'?")
        XCTAssertEqual(try parse("add", "-h"), .help(command: "indicators"))
    }

    /// `add` takes a name and a predicate, and a severity in any case, medium unless given. The name is trimmed.
    func testAdd() throws {
        XCTAssertEqual(try parse("add", "--name", " Curl ", "--predicate", Self.curl),
                       .indicators(.add(name: "Curl", predicate: Self.curl, severity: .medium)))
        XCTAssertEqual(try parse("add", "--severity=HIGH", "--predicate=\(Self.curl)", "--name=Curl"),
                       .indicators(.add(name: "Curl", predicate: Self.curl, severity: .high)))
        XCTAssertEqual(try parse("add", "--name", "Curl", "--predicate", Self.curl, "--severity", "low"),
                       .indicators(.add(name: "Curl", predicate: Self.curl, severity: .low)))
    }

    /// What `add` refuses: an indicator that can't be used exits 65, as the Security Extension's refusal of one does,
    /// and says why the Security Extension can't run its predicate. A command line that can't be read exits 64.
    func testAddRefusals() throws {
        XCTAssertEqual(usageError("add", "--predicate", Self.curl), "indicators add needs --name NAME.")
        XCTAssertEqual(usageError("add", "--name", "  ", "--predicate", Self.curl), "indicators add needs --name NAME.")
        XCTAssertEqual(usageError("add", "--name", "Curl"), "indicators add needs --predicate PREDICATE.")
        XCTAssertEqual(usageError("add", "--name", "A", "--name", "B"), "Give --name once.")
        XCTAssertEqual(usageError("add", "Curl"), "indicators add takes --name and --predicate, not 'Curl'.")
        XCTAssertEqual(usageError("add", "--tactic", "x"),
                       "Unknown option '--tactic' for indicators add.")
        XCTAssertEqual(usageError("add", "--name", "Curl", "--predicate", Self.curl, "--severity", "critical"),
                       "--severity must be low, medium or high, not 'critical'.")
        XCTAssertEqual(usageError("add", "--name", String(repeating: "n", count: Indicator.Limits.name + 1),
                                  "--predicate", Self.curl),
                       "The name is longer than \(Indicator.Limits.name) characters.")
        let untyped = try XCTUnwrap(usageError("add", "--name", "Curl", "--predicate",
                                               #"process.executable.path ENDSWITH "/curl""#))
        XCTAssertTrue(untyped.hasPrefix("The Security Extension can't run the predicate. "), untyped)
        XCTAssertEqual(untyped, "The Security Extension can't run the predicate. \(SensorProblem.untyped)")

        let data = [["add", "--name", "Curl", "--predicate", "process.executable.path == 'x'"],
                    ["add", "--name", "Curl", "--predicate", Self.curl, "--severity", "nope"],
                    ["add", "--name", String(repeating: "n", count: 200), "--predicate", Self.curl]]
        data.forEach { XCTAssertEqual(exitStatus($0), .dataError, $0.joined(separator: " ")) }
        let usage = [["add"], ["add", "--name", "Curl"], ["add", "x"], ["add", "--name"], ["list", "x"], ["nope"], []]
        usage.forEach { XCTAssertEqual(exitStatus($0), .usage, $0.joined(separator: " ")) }
    }

    /// `import FILE|- [--replace] [--yes]`.
    func testImport() throws {
        XCTAssertEqual(try parse("import", "mine.json"),
                       .indicators(.importFile(path: "mine.json", replace: false, confirmed: false)))
        XCTAssertEqual(try parse("import", "--replace", "-"),
                       .indicators(.importFile(path: "-", replace: true, confirmed: false)))
        XCTAssertEqual(try parse("import", "--yes", "mine.json", "--replace"),
                       .indicators(.importFile(path: "mine.json", replace: true, confirmed: true)))
        XCTAssertEqual(usageError("import", "a", "--replace=1"), "--replace takes no value.")
        XCTAssertEqual(usageError("import"), "indicators import needs a file, or - for standard input.")
        XCTAssertEqual(usageError("import", "a", "b"), "indicators import takes one file, not also 'b'.")
        XCTAssertEqual(usageError("import", "a", "--merge"), "Unknown option '--merge' for indicators import.")
    }

    /// `remove`, `enable` and `disable` take one or more IDs or names, in order, a name that starts with a dash after
    /// `--`, and no options.
    func testReferences() throws {
        let id = UUID().uuidString
        XCTAssertEqual(try parse("remove", id, "Plist modified"), .indicators(.remove([id, "Plist modified"])))
        XCTAssertEqual(try parse("enable", "A"), .indicators(.enable(["A"])))
        XCTAssertEqual(try parse("disable", "--", "-odd", "B"), .indicators(.disable(["-odd", "B"])))
        XCTAssertEqual(usageError("remove"), "indicators remove needs an indicator's ID or name.")
        XCTAssertEqual(usageError("enable", ""), "An indicator's name can't be empty.")
        XCTAssertEqual(usageError("disable", "A", "--yes"), "Unknown option '--yes' for indicators disable.")
        for subcommand in ["remove", "enable", "disable"] {
            XCTAssertEqual(exitStatus([subcommand]), .usage, subcommand)
        }
    }

    /// The help lists every indicators command and names every option they take, and the overview names the
    /// commands that need root as a list.
    func testTheHelpNamesEverything() {
        let help = CommandLineHelp.text(for: "indicators")
        for name in IndicatorInvocation.Name.allCases {
            XCTAssertTrue(help.contains("  \(name.rawValue)"), name.rawValue)
        }
        for option in Set(IndicatorInvocation.Name.allCases.flatMap(CommandLineOption.indicators).map(\.name)) {
            let whole = "(?<![-\\w])\(NSRegularExpression.escapedPattern(for: option))(?![-\\w])"
            XCTAssertNotNil(help.range(of: whole, options: .regularExpression), option)
        }
        XCTAssertTrue(help.hasPrefix("Usage: sudo macmonitor indicators list|show|add|edit|import|remove|enable|"
                                     + "disable|export"))
        XCTAssertTrue(CommandLineHelp.text(for: nil).contains(" stream, mute and indicators need root: "))
        XCTAssertNil(IndicatorCompiler.problem(with: Self.curl), "the help's kind of predicate runs")
    }
}
