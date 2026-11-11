//
//  IndicatorConfirmationTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Asking before an import or an edit from a file
/// Pins what `macmonitor indicators import` and `edit --file` ask before they change the set every user's capture and
/// every stream run: how many indicators it adds, removes and changes, and which of Mac Monitor's own it removes,
/// turns off or replaces. Without a terminal it needs `--yes` (64), and a no is 1, both leaving the set as it was.
final class IndicatorConfirmationTests: XCTestCase {
    private var savedMutes = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))
    private var savedIndicators: SavedIndicatorSet?

    /// A mute set and an indicator set in fresh directories.
    ///
    /// - Throws: If a directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        savedMutes = SavedMuteSet(testing: try makeMuteStore())
        savedIndicators = try makeSavedIndicatorSet()
    }

    /// Run one indicators command against this test's sets and wait for it.
    ///
    /// - Parameters:
    ///   - invocation: The command.
    ///   - confirm: Answers the question `import` asks: by default there's no one to ask.
    /// - Returns: What it did.
    private func run(_ invocation: IndicatorInvocation,
                     confirm: @escaping (String) -> Bool? = { _ in nil }) -> IndicatorRun {
        runIndicators(invocation, savedMutes: savedMutes, savedIndicators: savedIndicators!, confirm: confirm)
    }

    /// An indicator of the user's own.
    private let own = Indicator(name: "Curl", description: "", symbol: "star", color: .red,
                                predicate: IndicatorCommandLineTests.curl)

    /// `--replace` with a file of one indicator says it removes every shipped one, names the first few, and asks.
    /// With no one to ask it's 64, a no is 1, and a yes replaces the set.
    func testReplaceAsksFirst() throws {
        let replacing = try indicatorFile(of: [own], named: "mine.json")
        let invocation = IndicatorInvocation.importFile(path: replacing.path, replace: true)
        let unasked = try XCTUnwrap(run(invocation).failure)
        XCTAssertEqual(unasked, CommandLineFailure(.usage, """
            'indicators import' changes the indicators Mac Monitor and every stream follow, and there's no terminal \
            to ask at. Add --yes to go ahead.
            """))
        XCTAssertEqual(run(invocation, confirm: { _ in false }).failure, .declined)
        XCTAssertEqual(run(.list()).output.split(separator: "\n").count, Indicator.defaults.count + 1)

        let questions = DiagnosticLines()
        let replaced = run(invocation) { questions.append($0); return true }
        XCTAssertEqual(replaced.output, "Replaced this Mac's indicators with the file's: 1 indicator now.\n")
        let count = Indicator.defaults.count
        let first = Indicator.defaults.prefix(3).map { TerminalSafeText.quoted($0.name) }.joined(separator: ", ")
        XCTAssertEqual(questions.all, ["""
            Replace this Mac's indicators with the 1 indicator from “\(replacing.path)”?
            It adds 1 indicator, removes \(count) and changes 0: \(count) indicators now, 1 after.
            Of Mac Monitor's own indicators, it removes \(count) (\(first) and \(count - 3) more).
            \(IndicatorCommand.reach)
            """])
    }

    /// Without `--replace`, an import that changes a shipped indicator's rule and turns it off says so by name.
    func testMergeNamesTheShippedIndicatorsItChanges() throws {
        var edited = try XCTUnwrap(Indicator.defaults.first { $0.name == "Plist modified" && $0.isEnabled })
        edited.predicate += #" AND process.executable.path != "/usr/bin/true""#
        edited.isEnabled = false
        let merging = try indicatorFile(of: [edited, own], named: "edited.json")
        let questions = DiagnosticLines()
        let merged = run(.importFile(path: merging.path, replace: false)) { questions.append($0); return true }
        XCTAssertEqual(merged.output, "Added the file's indicators to this Mac's: \(Indicator.defaults.count + 1) "
                       + "indicators now.\n")
        let count = Indicator.defaults.count
        XCTAssertEqual(questions.all, ["""
            Add the 2 indicators from “\(merging.path)” to this Mac's indicators? Each replaces the indicator with its \
            ID.
            It adds 1 indicator, removes 0 and changes 1: \(count) indicators now, \(count + 1) after.
            Of Mac Monitor's own indicators, it turns off 1 (“Plist modified”) and replaces 1 (“Plist modified”).
            \(IndicatorCommand.reach)
            """])
        XCTAssertTrue(run(.list()).rows.contains { $0.hasPrefix("off ") && $0.hasSuffix("   Plist modified") })
    }

    /// `edit --file` asks first, naming the fields it changes and the shipped indicator whose rule it replaces. With
    /// no one to ask it's 64, a no is 1, both changing nothing, and a yes, or `--yes`, makes the edit.
    func testEditFromAFileAsksFirst() throws {
        let plist = try XCTUnwrap(Indicator.defaults.first { $0.name == "Plist modified" })
        let file = try JSONSerialization.data(withJSONObject: ["predicate": IndicatorCommandLineTests.curl,
                                                               "symbol": "star"])
        let edit = { (confirmed: Bool, confirm: @escaping (String) -> Bool?) in
            self.runIndicators(.edit(IndicatorEdit(plist.name, .file("one.json", confirmed: confirmed))),
                          savedMutes: self.savedMutes, savedIndicators: self.savedIndicators!,
                          readFile: { _ in file }, confirm: confirm)
        }
        XCTAssertEqual(edit(false) { _ in nil }.failure, CommandLineFailure(.usage, """
            'indicators edit' changes the indicator Mac Monitor and every stream follow, and there's no terminal to \
            ask at. Add --yes to go ahead.
            """))
        XCTAssertEqual(edit(false) { _ in false }.failure, .declined)
        XCTAssertEqual(try IndicatorExchange.indicators(from: Data(run(.export()).output.utf8)), Indicator.defaults)

        let questions = DiagnosticLines()
        let edited = edit(false) { questions.append($0); return true }
        XCTAssertTrue(edited.output.hasPrefix("Changed “Plist modified” ("), edited.output)
        let count = Indicator.defaults.count
        XCTAssertEqual(questions.all, ["""
            Change “Plist modified”'s symbol and predicate from “one.json”?
            It adds 0 indicators, removes 0 and changes 1: \(count) indicators now, \(count) after.
            Of Mac Monitor's own indicators, it replaces 1 (“Plist modified”).
            \(IndicatorCommand.reach)
            """])
        let restored = runIndicators(.edit(IndicatorEdit(plist.name, .restore)), savedMutes: savedMutes,
                                     savedIndicators: savedIndicators!)
        XCTAssertNoThrow(try restored.result?.get())
        XCTAssertNoThrow(try edit(true) { _ in XCTFail("asked"); return false }.result?.get())
    }

    /// What a change counts: identities added and removed, and those whose indicator changes, a switch alone
    /// included. Only a change to a rule replaces a shipped one, and only on to off turns one off.
    func testTheChangeCountsByIdentity() {
        var defaults = Array(Indicator.defaults.prefix(5))
        let current = defaults
        defaults[0].isEnabled.toggle()
        defaults[1].severity = defaults[1].severity == .high ? .low : .high
        defaults[2].predicate += " AND event_type >= 0"
        defaults.remove(at: 3)
        let change = IndicatorSetChange(from: current, to: defaults + [own])
        XCTAssertEqual([change.added, change.removed, change.changed, change.before, change.after], [1, 1, 3, 5, 5])
        XCTAssertEqual(change.shippedRemoved, [current[3].name])
        XCTAssertEqual(change.shippedTurnedOff, current[0].isEnabled ? [current[0].name] : [])
        XCTAssertEqual(change.shippedReplaced, [current[2].name])
        XCTAssertFalse(change.isEmpty)
        XCTAssertTrue(IndicatorSetChange(from: current, to: current).isEmpty)
        XCTAssertEqual(IndicatorSetChange(from: current, to: current).description,
                       "It adds 0 indicators, removes 0 and changes 0: 5 indicators now, 5 after.")
        XCTAssertEqual(IndicatorSetChange.listing(["A"]), "“A”")
        XCTAssertEqual(IndicatorSetChange.listing(["A", "B"]), "“A” and “B”")
        XCTAssertEqual(IndicatorSetChange.listing(["A", "B", "C"]), "“A”, “B” and “C”")
        XCTAssertEqual(IndicatorSetChange.listing(["A", "B", "C", "D\u{1B}"]), #"“A”, “B”, “C” and 1 more"#)
        XCTAssertEqual(IndicatorSetChange.listing(["\u{1B}x"]), #"“\x1Bx”"#)
    }
}
