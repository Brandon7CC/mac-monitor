//
//  IndicatorEditCommandTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - macmonitor indicators edit, end to end
/// Runs `macmonitor indicators edit` and `export ID|NAME` end to end in one process, over a real NSXPC connection to
/// ``StreamService`` and a real indicator set: what each edit changes and says, the identity it keeps, the names it
/// refuses, `--restore`, edits from a file, and who may make them.
final class IndicatorEditCommandTests: XCTestCase {
    private var savedMutes = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))
    private var savedIndicators: SavedIndicatorSet?
    /// How many indicators Mac Monitor ships.
    private let shipped = Indicator.defaults.count
    /// The shipped indicator most tests edit.
    private let plist = Indicator.defaults.first { $0.name == "Plist modified" }!

    /// A mute set and an indicator set in fresh directories.
    ///
    /// - Throws: If a directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        savedMutes = SavedMuteSet(testing: try makeMuteStore())
        savedIndicators = try makeSavedIndicatorSet()
    }

    /// Run one indicators command against this test's sets and wait for it. Nothing may ask.
    ///
    /// - Parameters:
    ///   - invocation: The command.
    ///   - grant: What the caller may do: everything, as root may.
    ///   - file: What every file read holds, as JSON, if anything.
    /// - Returns: What it did.
    private func run(_ invocation: IndicatorInvocation, grant: CommandLineGrant = .everything,
                     file: Any? = nil) -> IndicatorRun {
        let data = file.flatMap { try? JSONSerialization.data(withJSONObject: $0, options: .fragmentsAllowed) }
        return runIndicators(invocation, savedMutes: savedMutes, savedIndicators: savedIndicators!, grant: grant,
                             readFile: { _ in data ?? Data() }) { _ in
            XCTFail("asked")
            return false
        }
    }

    /// Edit an indicator from its options.
    ///
    /// - Parameters:
    ///   - reference: Its ID or name.
    ///   - values: The options' values, as the parser keeps them.
    /// - Returns: What it did.
    private func edit(_ reference: String, _ values: [Indicator.EditableField: String]) -> IndicatorRun {
        run(.edit(IndicatorEdit(reference, .values(values))))
    }

    /// The set as it stands.
    ///
    /// - Returns: Its indicators, in order.
    /// - Throws: If `export` doesn't write an indicator file.
    private func current() throws -> [Indicator] {
        try IndicatorExchange.indicators(from: Data(run(.export()).output.utf8))
    }

    /// An edit keeps the indicator's identity, place and switch, so records, `--indicator ID` and the views stay
    /// with it, and says what it changed: a severity from and to, a predicate by name. A change to a shipped
    /// indicator's rule says it no longer follows Mac Monitor's updates, and how to bring it back.
    func testEditKeepsIdentityAndSaysWhatChanged() throws {
        let edited = edit(plist.name.uppercased(), [.predicate: IndicatorCommandLineTests.curl, .severity: "high"])
        XCTAssertEqual(edited.output, """
            Changed “Plist modified” (\(plist.id.uuidString)): predicate, severity low to high. \(shipped) indicators \
            now.

            """)
        XCTAssertEqual(edited.errors, ["""
            macmonitor: “Plist modified” is one of Mac Monitor's own. Mac Monitor updates no longer change it: \
            'macmonitor indicators edit \(plist.id.uuidString) --restore' brings back this build's version.
            """])
        let after = try current()
        let index = try XCTUnwrap(Indicator.defaults.firstIndex(of: plist))
        XCTAssertEqual(after[index].id, plist.id)
        XCTAssertEqual(after[index].isEnabled, plist.isEnabled)
        XCTAssertEqual(plist.changedFields(to: after[index]), [.predicate, .severity])
        XCTAssertEqual(after.map(\.id), Indicator.defaults.map(\.id))
    }

    /// A tactic, technique or severity edit keeps a shipped indicator following Mac Monitor's updates, so it says
    /// nothing more, and says nothing again for one whose rule an earlier edit already changed. Tactics and
    /// techniques show from and to, none included.
    func testAClassificationEditHasNoWarning() throws {
        let edited = edit(plist.id.uuidString, [.tactic: "persistence", .technique: ""])
        XCTAssertEqual(edited.output, """
            Changed “Plist modified” (\(plist.id.uuidString)): tactic Defense Evasion to Persistence, technique \
            T1647 to none. \(shipped) indicators now.

            """)
        XCTAssertEqual(edited.errors, [])
        XCTAssertEqual(edit(plist.name, [.description: "Mine."]).errors.count, 1)
        let severity = edit(plist.name, [.severity: "high"])
        XCTAssertNoThrow(try severity.result?.get())
        XCTAssertEqual(severity.errors, [])
    }

    /// `--restore` puts every editable field back as this build ships it, quietly, and says so when there's nothing
    /// to put back. One of the user's own has nothing to restore (65).
    func testRestore() throws {
        XCTAssertNoThrow(try edit(plist.name, [.name: "Plist written", .severity: "high"]).result?.get())
        let restored = run(.edit(IndicatorEdit(plist.id.uuidString, .restore)))
        XCTAssertEqual(restored.output, """
            Restored “Plist written” (\(plist.id.uuidString)): name, severity high to low. \(shipped) indicators now.

            """)
        XCTAssertEqual(restored.errors, [])
        XCTAssertEqual(try current(), Indicator.defaults)
        XCTAssertEqual(run(.edit(IndicatorEdit(plist.name, .restore))).output,
                       "“Plist modified” is already Mac Monitor's own.\n")

        XCTAssertNoThrow(try run(.add(name: "Curl", predicate: IndicatorCommandLineTests.curl)).result?.get())
        XCTAssertEqual(run(.edit(IndicatorEdit("curl", .restore))).failure, CommandLineFailure(.dataError, """
            “Curl” isn't one of Mac Monitor's own, so it has nothing to restore.
            """))
    }

    /// A rename onto another indicator's name, in any case, is refused (65) and changes nothing. A change of case
    /// to its own name is a rename like any other.
    func testEditRefusesATakenNameButAllowsItsOwnCase() throws {
        let keychain = try XCTUnwrap(Indicator.defaults.first { $0.name == "Keychain opened" })
        XCTAssertEqual(edit(plist.name, [.name: "KEYCHAIN OPENED"]).failure, CommandLineFailure(.dataError, """
            An indicator is already named \(IndicatorTable.describe(keychain)). Choose another name.
            """))
        XCTAssertEqual(try current(), Indicator.defaults)
        XCTAssertEqual(edit(plist.name, [.name: "PLIST MODIFIED"]).output, """
            Changed “Plist modified” (\(plist.id.uuidString)): name. \(shipped) indicators now.

            """)
        XCTAssertTrue(try current().contains { $0.name == "PLIST MODIFIED" })
    }

    /// The indicator is found as `remove` finds one: a name two share is refused with their IDs, and one no
    /// indicator has suggests the name meant. Both are 65.
    func testEditFindsOneIndicator() throws {
        let twins = (0..<2).map { _ in ownIndicator("Twin", IndicatorCommandLineTests.curl) }
        let file = try indicatorFile(of: twins, named: "twins.json")
        XCTAssertNoThrow(try runIndicators(.importFile(path: file.path, replace: false, confirmed: true),
                                           savedMutes: savedMutes, savedIndicators: savedIndicators!).result?.get())
        XCTAssertEqual(edit("twin", [.severity: "high"]).failure, CommandLineFailure(.dataError, """
            2 indicators are named “twin”. Name the one you mean by its ID: \(twins[0].id.uuidString), \
            \(twins[1].id.uuidString).
            """))
        XCTAssertEqual(edit("Plist modifed", [.severity: "high"]).failure, CommandLineFailure(.dataError, """
            No indicator has the ID or name “Plist modifed”. Did you mean 'Plist modified'? Run 'macmonitor \
            indicators list' to see them.
            """))
        XCTAssertEqual(edit(twins[1].id.uuidString, [.severity: "high"]).failure, nil)
    }

    /// An edit to what the indicator already has says so, succeeds, and changes nothing.
    func testEditNoChangeSaysSo() throws {
        let unchanged = edit(plist.name, [.severity: "low", .name: "Plist modified"])
        XCTAssertNoThrow(try unchanged.result?.get())
        XCTAssertEqual(unchanged.output, "“Plist modified” already has that.\n")
        XCTAssertEqual(try current(), Indicator.defaults)
    }

    /// `--file` takes the editable keys the file's one indicator has, and nothing else: not its switch, its views,
    /// nor a key this build doesn't know. `export ID` writes one to start from.
    func testEditFileTakesOnlyThePresentKeys() throws {
        let partial: [String: Any] = ["severity": "high", "isEnabled": !plist.isEnabled, "showsInGroups": true,
                                      "tableMark": "off", "tableMarks": [], "weight": 7]
        let edited = run(.edit(IndicatorEdit(plist.name, .file("one.json", confirmed: true))), file: partial)
        XCTAssertEqual(edited.output, """
            Changed “Plist modified” (\(plist.id.uuidString)): severity low to high. \(shipped) indicators now.

            """)
        var expected = plist
        expected.severity = .high
        XCTAssertEqual(try current().first { $0.id == plist.id }, expected)

        let exported = run(.export([plist.id.uuidString])).output
        XCTAssertEqual(try IndicatorExchange.indicators(from: Data(exported.utf8)), [expected])
        var entry = try XCTUnwrap(IndicatorExchange.entryObjects(from: Data(exported.utf8)).first)
        entry["symbol"] = "star"
        entry["tactic"] = NSNull()
        let file = ["format": IndicatorExchange.format, "version": IndicatorExchange.version,
                    "indicators": [entry]] as [String: Any]
        XCTAssertEqual(run(.edit(IndicatorEdit(plist.id.uuidString, .file("-", confirmed: true))), file: file).output,
                       """
                       Changed “Plist modified” (\(plist.id.uuidString)): symbol, tactic Defense Evasion to none. \
                       \(shipped) indicators now.

                       """)
    }

    /// What `--file` refuses (65), changing nothing: another indicator's identity, several indicators, a tactic or
    /// severity this build doesn't know, a blank name, another kind of rule, a value that can't be read, and what
    /// isn't indicators.
    func testEditFileRefusals() throws {
        let edit = IndicatorInvocation.edit(IndicatorEdit(plist.name, .file("one.json", confirmed: true)))
        let other = UUID().uuidString
        let refusals: [(Any, String)] = [
            (["id": other, "severity": "high"], "edit keeps an indicator's ID; “one.json”'s is \(other)."),
            ([["severity": "high"], ["severity": "low"]], "An edit takes one indicator; “one.json” has 2."),
            (["tactic": "stealth"], "“one.json” can't be used to edit an indicator. Its tactic 'stealth' isn't an "
                + "ATT&CK tactic."),
            (["severity": "critical"], "“one.json” can't be used to edit an indicator. Its severity must be low, "
                + "medium or high, not 'critical'."),
            (["severity": 3], "“one.json” can't be used to edit an indicator. Its severity must be low, medium or "
                + "high, not '3'."),
            (["name": "  "], "The name can't be empty."),
            (["name": ""], "The name can't be empty."),
            (["predicate": 3], "“one.json” can't be used to edit an indicator. An indicator in the file has a value "
                + "for predicate that can't be read."),
            (["format": "mutes", "indicators": []], "“one.json” can't be used to edit an indicator. The file isn't "
                + "Mac Monitor indicators."),
        ]
        for (file, message) in refusals {
            XCTAssertEqual(run(edit, file: file).failure, CommandLineFailure(.dataError, message), message)
        }
        let kind = try XCTUnwrap(run(edit, file: ["kind": "sequence", "severity": "high"]).failure)
        XCTAssertEqual(kind.exit, .dataError)
        XCTAssertTrue(kind.message.contains("It's a rule of kind sequence"), kind.message)
        let long = try XCTUnwrap(run(edit, file: ["name": String(repeating: "n", count: 200)]).failure)
        XCTAssertEqual(long.exit, .dataError)
        XCTAssertEqual(try current(), Indicator.defaults)
    }

    /// `export ID|NAME...` writes only the indicators named, in the order named, each once. One no indicator has is
    /// refused (65) and nothing is written.
    func testExportNamedIndicators() throws {
        let keychain = try XCTUnwrap(Indicator.defaults.first { $0.name == "Keychain opened" })
        let exported = run(.export(["keychain opened", plist.id.uuidString, keychain.id.uuidString]))
        XCTAssertEqual(try IndicatorExchange.indicators(from: Data(exported.output.utf8)), [keychain, plist])
        let unknown = run(.export(["Nope"]))
        XCTAssertEqual(unknown.failure?.exit, .dataError)
        XCTAssertEqual(unknown.output, "")
    }

    /// Names reach the terminal escaped, in an edit's answer and its warning.
    func testNamesAreEscaped() throws {
        let renamed = edit(plist.name, [.name: "Evil\u{1B}[31m"])
        XCTAssertTrue(renamed.output.hasPrefix("Changed “Plist modified” ("), renamed.output)
        let again = edit(plist.id.uuidString, [.symbol: "star"])
        XCTAssertTrue(again.output.hasPrefix(#"Changed “Evil\x1B[31m” ("#), again.output)
        XCTAssertTrue(again.errors.first?.contains(#"“Evil\x1B[31m” is one of"#) == true, "\(again.errors)")
        XCTAssertFalse((again.output + again.errors.joined()).unicodeScalars.contains { $0.value == 0x1B })
    }

    /// A caller who may only stream can't edit (77), and one who may change the set, as root may, can.
    func testAccess() throws {
        let values = IndicatorEdit.Change.values([.severity: "high"])
        let refused = try XCTUnwrap(run(.edit(IndicatorEdit(plist.name, values)), grant: .streaming).failure)
        XCTAssertEqual(refused.exit, .noPermission)
        XCTAssertEqual(refused.message, CommandLineAccess.needsChanges)
        XCTAssertEqual(try current(), Indicator.defaults)
        XCTAssertNoThrow(try run(.edit(IndicatorEdit(plist.name, values)), grant: .everything).result?.get())
    }
}
