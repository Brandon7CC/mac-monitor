//
//  IndicatorCommandTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - macmonitor indicators, end to end
/// Runs `macmonitor indicators` end to end in one process: ``IndicatorCommand`` and ``StreamClient`` over a real
/// NSXPC connection to ``StreamService``, whose indicator set is kept in a temporary directory.
final class IndicatorCommandTests: XCTestCase {
    private var savedMutes = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))
    private var savedIndicators: SavedIndicatorSet?
    /// How many indicators Mac Monitor ships.
    private let shipped = Indicator.defaults.count

    /// A mute set and an indicator set in fresh directories.
    ///
    /// - Throws: If a directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        savedMutes = SavedMuteSet(testing: try makeMuteStore())
        savedIndicators = try makeSavedIndicatorSet()
    }

    /// Run one indicators command against this test's sets and wait for it (``runIndicators(_:savedMutes:
    /// savedIndicators:grant:input:readFile:confirm:)``).
    ///
    /// - Parameters:
    ///   - invocation: The command.
    ///   - grant: What the caller may do: everything, as root may.
    ///   - input: What standard input holds, for `import -`.
    ///   - readFile: Reads a file to import, unless the real reader is wanted.
    ///   - confirm: Answers the question `import` asks: by default there's no one to ask.
    /// - Returns: What it did.
    private func run(_ invocation: IndicatorInvocation, grant: CommandLineGrant = .everything, input: Data = Data(),
                     readFile: ((String) throws -> Data)? = nil,
                     confirm: @escaping (String) -> Bool? = { _ in nil }) -> IndicatorRun {
        runIndicators(invocation, savedMutes: savedMutes, savedIndicators: savedIndicators!, grant: grant,
                      input: input, readFile: readFile, confirm: confirm)
    }

    /// The set's table rows, without the header.
    ///
    /// - Returns: The rows.
    private func rows() -> [String] {
        run(.list()).rows
    }

    /// `list` shows the set, which starts as Mac Monitor's own, one indicator a line under a header, each with its
    /// state, severity, ID and name, in the set's order.
    func testListShowsTheSet() throws {
        let listed = run(.list())
        XCTAssertNoThrow(try listed.result?.get())
        XCTAssertEqual(listed.errors, [])
        let lines = listed.output.split(separator: "\n").map(String.init)
        XCTAssertEqual(lines.count, shipped + 1)
        XCTAssertEqual(lines.first?.split(separator: " ", omittingEmptySubsequences: true),
                       ["STATE", "SEVERITY", "ID", "NAME"])
        for (line, indicator) in zip(lines.dropFirst(), Indicator.defaults) {
            let state = indicator.isEnabled ? "on " : "off "
            XCTAssertTrue(line.hasPrefix(state), line)
            XCTAssertTrue(line.contains(" \(indicator.severity.rawValue) "), line)
            XCTAssertTrue(line.contains(" \(indicator.id.uuidString) "), line)
            XCTAssertTrue(line.hasSuffix("   \(indicator.name)"), line)
        }
        XCTAssertTrue(Set(Indicator.defaults.map(\.severity)).count > 1, "the shipped set has several severities")
    }

    /// `add` adds an indicator, medium unless given a severity, which `list` and `export` show and `remove` by its
    /// name, ignoring case, takes out again.
    func testAddListExportAndRemove() throws {
        let added = run(.add(name: "Curl", predicate: IndicatorCommandLineTests.curl, severity: .high))
        XCTAssertNoThrow(try added.result?.get())
        XCTAssertTrue(added.output.hasPrefix("Added “Curl” (high, "), added.output)
        XCTAssertTrue(added.output.hasSuffix("). \(shipped + 1) indicators now.\n"), added.output)
        XCTAssertEqual(added.errors, [])
        let row = try XCTUnwrap(rows().last)
        XCTAssertTrue(row.hasPrefix("on ") && row.contains(" high ") && row.hasSuffix("   Curl"), row)

        let exported = try IndicatorExchange.indicators(from: Data(run(.export()).output.utf8))
        let curl = try XCTUnwrap(exported.last)
        XCTAssertEqual([curl.name, curl.predicate], ["Curl", IndicatorCommandLineTests.curl])
        XCTAssertEqual(curl.severity, .high)
        XCTAssertTrue(curl.isEnabled)
        XCTAssertTrue(added.output.contains(curl.id.uuidString))

        XCTAssertEqual(run(.add(name: "Medium", predicate: IndicatorCommandLineTests.curl)).failure, nil)
        XCTAssertTrue(try XCTUnwrap(rows().last).contains(" medium "))
        XCTAssertEqual(run(.remove(["curl", "MEDIUM"])).output,
                       "Removed “Curl” and “Medium”. \(shipped) indicators now.\n")
        XCTAssertEqual(rows().count, shipped)
    }

    /// `add` refuses a name the set has, in any case, so a name always finds one indicator: 65, and nothing changes.
    func testAddRefusesATakenName() throws {
        let taken = try XCTUnwrap(Indicator.defaults.first)
        let failure = try XCTUnwrap(run(.add(name: taken.name.uppercased(),
                                             predicate: IndicatorCommandLineTests.curl)).failure)
        XCTAssertEqual(failure.exit, .dataError)
        XCTAssertEqual(failure.message, """
            An indicator is already named \(IndicatorTable.describe(taken)). Choose another name.
            """)
        XCTAssertEqual(rows().count, shipped)
    }

    /// `remove` takes an ID too, refuses a name two indicators share and lists their IDs, and suggests the name meant
    /// for one no indicator has. Each refusal is 65 and changes nothing.
    func testRemoveFindsOneIndicatorEach() throws {
        let twins = (0..<2).map { _ in
            Indicator(name: "Twin", description: "", symbol: "star", color: .red,
                      predicate: IndicatorCommandLineTests.curl)
        }
        let file = try indicatorFile(of: twins, named: "twins.json")
        XCTAssertNoThrow(try run(.importFile(path: file.path, replace: false, confirmed: true)).result?.get())

        let ambiguous = try XCTUnwrap(run(.remove(["twin"])).failure)
        XCTAssertEqual(ambiguous.exit, .dataError)
        XCTAssertEqual(ambiguous.message, """
            2 indicators are named “twin”. Name the one you mean by its ID: \(twins[0].id.uuidString), \
            \(twins[1].id.uuidString).
            """)
        let plist = try XCTUnwrap(Indicator.defaults.first { $0.name == "Plist modified" })
        let unknown = try XCTUnwrap(run(.remove(["Plist modifed"])).failure)
        XCTAssertEqual(unknown, CommandLineFailure(.dataError, """
            No indicator has the ID or name “Plist modifed”. Did you mean 'Plist modified'? Run 'macmonitor \
            indicators list' to see them.
            """))
        XCTAssertEqual(rows().count, shipped + 2)

        let lowercased = twins[0].id.uuidString.lowercased()
        XCTAssertEqual(run(.remove([lowercased, twins[1].id.uuidString, lowercased])).output,
                       "Removed “Twin” and “Twin”. \(shipped) indicators now.\n")
        XCTAssertNoThrow(try run(.remove([plist.id.uuidString])).result?.get())
        XCTAssertFalse(rows().contains { $0.hasSuffix("   Plist modified") })
    }

    /// `show` writes every detail of each indicator named, by name or identity, with a blank line between them: its
    /// state, severity, tactic, technique, whether it's one of Mac Monitor's own, how the tables mark it, its
    /// description and its predicate. An indicator nothing names is refused, with the name meant.
    func testShowWritesEveryDetail() throws {
        let executable = try XCTUnwrap(Indicator.defaults.first { $0.name == "New executable" })
        let shown = run(.show(["new executable"]))
        XCTAssertNoThrow(try shown.result?.get())
        XCTAssertEqual(shown.output, """
            New executable
              ID             \(executable.id.uuidString)
              State          on
              Severity       medium
              Tactic         Execution (TA0002)
              Technique      T1204.002
              Default        yes
              Event tables   Dot, Symbol
              Description    \(executable.description)
              Predicate      \(executable.predicate)

            """)
        let plist = try XCTUnwrap(Indicator.defaults.first { $0.name == "Plist modified" })
        let both = run(.show([plist.id.uuidString, "New executable"])).output
        XCTAssertTrue(both.hasPrefix("Plist modified\n  ID             \(plist.id.uuidString)\n"))
        XCTAssertTrue(both.contains("\n\nNew executable\n"), "A blank line between indicators")
        XCTAssertNoThrow(try run(.disable(["Plist modified"])).result?.get())
        XCTAssertTrue(run(.show(["Plist modified"])).output.contains("  State          off\n"))
        let unknown = try XCTUnwrap(run(.show(["Plist modifed"])).failure)
        XCTAssertEqual(unknown.exit, .dataError)
        XCTAssertTrue(unknown.message.contains("Did you mean 'Plist modified'?"))
        var own = executable
        own.id = UUID()
        own.description = ""
        own.tactic = nil
        own.technique = nil
        let problem = IndicatorReply.Problem(id: own.id, reason: "Too long.")
        let details = IndicatorTable.details([own], problems: [problem])
        XCTAssertTrue(details.contains("  State          not run: Too long.\n"))
        XCTAssertTrue(details.contains("  Tactic         none\n"))
        XCTAssertTrue(details.contains("  Technique      none\n"))
        XCTAssertTrue(details.contains("  Default        no\n"))
        XCTAssertTrue(details.contains("  Description    none\n"))
    }

    /// `disable` and `enable` turn indicators off and on, say which already were, and `list` shows each one's state.
    func testEnableAndDisable() throws {
        let plist = try XCTUnwrap(Indicator.defaults.first { $0.name == "Plist modified" && $0.isEnabled })
        XCTAssertEqual(run(.disable(["plist modified"])).output,
                       "Turned off “Plist modified”. \(shipped) indicators now.\n")
        XCTAssertTrue(rows().contains { $0.hasPrefix("off ") && $0.hasSuffix("   Plist modified") })
        XCTAssertEqual(run(.disable([plist.id.uuidString])).output,
                       "Already off: “Plist modified”. \(shipped) indicators now.\n")
        let other = try XCTUnwrap(Indicator.defaults.first { $0.isEnabled && $0.id != plist.id })
        XCTAssertEqual(run(.enable([plist.id.uuidString, other.name])).output, """
            Turned on “Plist modified”. Already on: \(TerminalSafeText.quoted(other.name)). \(shipped) indicators now.

            """)
        XCTAssertTrue(rows().contains { $0.hasPrefix("on ") && $0.hasSuffix("   Plist modified") })
    }

    /// `enable` of an indicator the Security Extension can't run turns it on and says it never matches, as `add` and
    /// `import` do. `disable` of it doesn't: off, it isn't meant to match.
    func testEnablingAnIndicatorThatCantRunSaysSo() throws {
        let unrun = Indicator(name: "Unrun", description: "", symbol: "star", color: .red,
                              predicate: #"process.executable.path ENDSWITH "/curl""#, isEnabled: false)
        let file = try indicatorFile(of: [unrun], named: "unrun.json")
        let imported = run(.importFile(path: file.path, replace: false, confirmed: true))
        XCTAssertNoThrow(try imported.result?.get())
        let warning = """
            macmonitor: The Security Extension can't run “Unrun”, so it never matches. \(SensorProblem.untyped)
            """
        XCTAssertEqual(imported.errors, [warning])

        let enabled = run(.enable(["unrun"]))
        XCTAssertEqual(enabled.output, "Turned on “Unrun”. \(shipped + 1) indicators now.\n")
        XCTAssertEqual(enabled.errors, [warning])
        let disabled = run(.disable([unrun.id.uuidString]))
        XCTAssertEqual(disabled.output, "Turned off “Unrun”. \(shipped + 1) indicators now.\n")
        XCTAssertEqual(disabled.errors, [])
    }

    /// `export` writes the indicator file `list --format json` writes. Importing it back, from a file or standard
    /// input, changes nothing, so it doesn't ask.
    func testExportAndImportRoundTrip() throws {
        _ = run(.add(name: "Curl", predicate: IndicatorCommandLineTests.curl, severity: .low))
        let exported = run(.export()).output
        XCTAssertEqual(run(.list(format: .json)).output, exported)
        XCTAssertEqual(try IndicatorExchange.indicators(from: Data(exported.utf8)).count, shipped + 1)
        let file = try temporaryFile(containing: exported, named: "indicators.json")
        let unasked: (String) -> Bool? = { _ in XCTFail("asked about nothing"); return false }
        for replace in [false, true] {
            XCTAssertEqual(run(.importFile(path: file.path, replace: replace), confirm: unasked).output,
                           "This Mac's indicators already had the file's: \(shipped + 1) indicators now.\n")
        }
        XCTAssertEqual(run(.importFile(path: "-", replace: false), input: Data(exported.utf8),
                           confirm: unasked).output,
                       "This Mac's indicators already had the file's: \(shipped + 1) indicators now.\n")
    }

    /// `import` reads at most 4 MiB, refuses what it can't read (66) and what isn't indicators (65), and a file the
    /// Security Extension refuses (65), each leaving the set as it was.
    func testImportRefusals() throws {
        let tooLarge = run(.importFile(path: "big.json", replace: false, confirmed: true),
                           readFile: { _ in Data(count: IndicatorLimits.maxFileBytes + 1) })
        XCTAssertEqual(tooLarge.failure, CommandLineFailure(.dataError, """
            “big.json” is larger than 4 MiB, so it wasn't imported.
            """))
        let directory = try makeTemporaryDirectory()
        XCTAssertEqual(run(.importFile(path: directory.path, replace: false, confirmed: true)).failure,
                       CommandLineFailure(.noInput, "“\(directory.path)” couldn't be read: it isn't a regular file."))
        XCTAssertEqual(run(.importFile(path: "/nonexistent/x.json", replace: false, confirmed: true)).failure?.exit,
                       .noInput)
        let mutes = try temporaryFile(containing: #"{"format":"mutes","indicators":[]}"#, named: "mutes.json")
        XCTAssertEqual(run(.importFile(path: mutes.path, replace: false, confirmed: true)).failure,
                       CommandLineFailure(.dataError, """
                        “\(mutes.path)” couldn't be imported. The file isn't Mac Monitor indicators.
                        """))
        var unknownType = Indicator.defaults[0]
        unknownType.id = UUID()
        unknownType.predicate = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_NOPE""#
        let refused = try indicatorFile(of: [unknownType], named: "refused.json")
        XCTAssertEqual(run(.importFile(path: refused.path, replace: false, confirmed: true)).failure?.exit,
                       .dataError)
        XCTAssertEqual(rows().count, shipped)
    }

    /// The real reader reads a regular file or standard input, at most one byte past the cap, and refuses anything
    /// else, such as a folder, without reading it.
    func testFileInputReadsRegularFilesOnly() throws {
        let file = try temporaryFile(containing: "0123456789", named: "ten.txt")
        XCTAssertEqual(try FileInput.read(file.path, upTo: 4), Data("01234".utf8))
        XCTAssertEqual(try FileInput.read(file.path, upTo: 100), Data("0123456789".utf8))
        XCTAssertThrowsError(try FileInput.read(try makeTemporaryDirectory().path, upTo: 4)) {
            XCTAssertEqual(($0 as? CocoaError)?.code, .fileReadUnsupportedScheme)
        }
        XCTAssertThrowsError(try FileInput.read("/nonexistent/file", upTo: 4)) {
            XCTAssertEqual(($0 as? POSIXError)?.code, .ENOENT)
        }
    }

    /// What reaches the terminal is escaped: a name with an escape sequence, in `add`'s answer and `list`'s table.
    func testNamesAreEscapedForATerminal() throws {
        let added = run(.add(name: "Evil\u{1B}[31m", predicate: IndicatorCommandLineTests.curl))
        XCTAssertTrue(added.output.hasPrefix(#"Added “Evil\x1B[31m” (medium, "#), added.output)
        let listed = run(.list()).output
        XCTAssertTrue(listed.contains(#"   Evil\x1B[31m"#))
        XCTAssertFalse((added.output + listed).unicodeScalars.contains { $0.value == 0x1B })
    }

    /// A Security Extension older than 3.1 has no indicators: every indicators command says to update it (69).
    func testAnExtensionWithoutIndicators() throws {
        let older = ServiceBeforeIndicators()
        for invocation in [IndicatorInvocation.list(), .export(), .remove(["Plist modified"])] {
            let client = StreamClient(connection: NSXPCConnection(listenerEndpoint: older.endpoint), requirement: nil)
            client.activate(receiving: TestStreamReader()) { _ in }
            let command = IndicatorCommand(client: client, output: BufferOutput(), diagnose: { _ in },
                                           timeout: .seconds(2))
            let result = try awaitCallback(timeout: 10) { command.run(invocation, completion: $0) }
            client.invalidate()
            XCTAssertEqual(result.failure, .indicatorsUnanswered, "\(invocation)")
        }
        XCTAssertEqual(older.streamRequests, 0)
    }

    /// A caller who isn't root and may only stream can list the set but not change it (77), and one refused
    /// outright can't even list it.
    func testAccess() throws {
        XCTAssertNoThrow(try run(.list(), grant: .streaming).result?.get())
        for change in [IndicatorInvocation.add(name: "Curl", predicate: IndicatorCommandLineTests.curl),
                       .disable(["Plist modified"]), .remove(["Plist modified"])] {
            let refused = try XCTUnwrap(run(change, grant: .streaming).failure, "\(change)")
            XCTAssertEqual(refused.exit, .noPermission)
            XCTAssertEqual(refused.message, CommandLineAccess.needsChanges)
        }
        let outright = try XCTUnwrap(run(.list(), grant: .refused(CommandLineAccess.needsRoot)).failure)
        XCTAssertEqual(outright, CommandLineFailure(.noPermission, CommandLineAccess.needsRoot))
        XCTAssertEqual(rows().count, shipped)
    }
}
