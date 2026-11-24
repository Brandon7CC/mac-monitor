//
//  IndicatorPackInstallCommandTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/16/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Installing a pack from the command line
/// Pins `macmonitor indicators pack install`: it has the Security Extension check the pack, says what installing it
/// would change and asks, installs it, and says which release this Mac then has. A pack the Security Extension
/// refuses exits 65 with its reason. The build these tests stand for links in ``XCTestCase/linkedFixtures()``.
final class IndicatorPackInstallCommandTests: XCTestCase {
    private var savedMutes = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))
    private var savedIndicators: SavedIndicatorSet?
    /// The indicators the build links in.
    private var linked: [Indicator] = []

    /// Pack updates are on for these tests, and held back again after each (``IndicatorPackUpdates/isAvailable``).
    override func tearDown() {
        IndicatorPackUpdates.isAvailable = false
        super.tearDown()
    }

    /// A mute set, and an indicator set that trusts the fixtures' signer, in fresh directories.
    ///
    /// - Throws: If a directory can't be created or a fixture is missing.
    override func setUpWithError() throws {
        try super.setUpWithError()
        IndicatorPackUpdates.isAvailable = true
        savedMutes = SavedMuteSet(testing: try makeMuteStore())
        linked = try linkedFixtures()
        savedIndicators = try makeSavedIndicatorSet(defaults: linked, verifier: try packVerifier())
    }

    /// Run one indicators command against this test's sets and wait for it.
    ///
    /// - Parameters:
    ///   - invocation: The command.
    ///   - grant: What the caller may do: everything, as root may.
    ///   - input: What standard input holds.
    ///   - confirm: Answers the question it asks: by default there's no one to ask.
    /// - Returns: What it did.
    private func run(_ invocation: IndicatorInvocation, grant: CommandLineGrant = .everything, input: Data = Data(),
                     confirm: @escaping (String) -> Bool? = { _ in nil }) -> IndicatorRun {
        runIndicators(invocation, savedMutes: savedMutes, savedIndicators: savedIndicators!, grant: grant,
                      input: input, confirm: confirm)
    }

    /// The names `indicators list` shows, in order.
    ///
    /// - Returns: The names.
    /// - Throws: A failure when the set can't be exported.
    private func listed() throws -> [String] {
        try IndicatorExchange.indicators(from: Data(run(.export()).output.utf8)).map(\.name)
    }

    /// It says what the pack would change, naming the build's indicator whose rule it replaces and the one it
    /// removes, and asks. With no one to ask it's 64, a no is 1, both changing nothing, and a yes installs it.
    func testItAsksFirst() throws {
        let path = try fixtureURL("indicator-pack-2.json").path
        let invocation = IndicatorInvocation.pack(.install(path: path))
        XCTAssertEqual(run(invocation).failure, CommandLineFailure(.usage, """
            'indicators pack install' changes the indicators Mac Monitor and every stream follow, and there's no \
            terminal to ask at. Add --yes to go ahead.
            """))
        XCTAssertEqual(run(invocation, confirm: { _ in false }).failure, .declined)
        XCTAssertEqual(try listed(), linked.map(\.name))

        let questions = DiagnosticLines()
        let installed = run(invocation) { questions.append($0); return true }
        XCTAssertNil(installed.failure)
        XCTAssertEqual(installed.output, "Installed indicator pack 2 from “\(path)”: 3 indicators now.\n")
        XCTAssertEqual(questions.all, ["""
            Install indicator pack 2 from “\(path)”?
            It adds 1 indicator, removes 1 and changes 1: 3 indicators now, 3 after.
            Of Mac Monitor's own indicators, it removes 1 (“Fixture dropped”) and replaces 1 (“Fixture program \
            ran”).
            \(IndicatorCommand.reach)
            """])
        XCTAssertEqual(try listed(), try releaseFixture(2).pack.indicators.map(\.name))
    }

    /// `--yes` installs without asking, standard input is read for `-`, and a release with an entry that needs a
    /// newer Mac Monitor says so.
    func testYesInstallsWithoutAsking() throws {
        let installed = run(.pack(.install(path: "-", confirmed: true)), input: try releaseFixture(3).file) { _ in
            XCTFail("--yes asks nothing")
            return false
        }
        XCTAssertNil(installed.failure)
        XCTAssertEqual(installed.output, """
            Installed indicator pack 3 from standard input: 3 indicators now. 1 of its indicators needs a newer Mac \
            Monitor, and isn't run.

            """)
    }

    /// Once a pack is installed, its indicators are Mac Monitor's own: `show` says so of one the build doesn't have,
    /// and `edit --restore` puts an edited one back as the pack has it.
    func testAnInstalledPacksIndicatorsAreMacMonitorsOwn() throws {
        let pack = try releaseFixture(2).pack
        XCTAssertNil(run(.pack(.install(path: try fixtureURL("indicator-pack-2.json").path, confirmed: true))).failure)
        let added = pack.indicators[2]
        XCTAssertTrue(run(.show([added.name])).output.contains("Default        yes\n"))
        XCTAssertNil(run(.edit(IndicatorEdit(added.name, .values([.severity: "high"])))).failure)
        let restored = run(.edit(IndicatorEdit(added.name, .restore)))
        XCTAssertNil(restored.failure)
        XCTAssertTrue(restored.output.hasPrefix("Restored “\(added.name)”"), restored.output)
    }

    /// A pack the Security Extension refuses exits 65 with its reason, whether it's asked about first or not, and
    /// changes nothing: one that isn't Developer ID's, one that's no later, and a file that isn't a pack.
    func testARefusedPackExits65() throws {
        let other = try fixtureURL("indicator-pack-not-developer-id.json").path
        for confirmed in [false, true] {
            let refused = run(.pack(.install(path: other, confirmed: confirmed)), confirm: { _ in true })
            XCTAssertEqual(refused.failure, CommandLineFailure(.dataError, """
                The pack wasn't installed. It isn't signed with a Developer ID Application certificate from Apple.
                """), "\(confirmed)")
            XCTAssertEqual(refused.output, "")
        }
        let path = try fixtureURL("indicator-pack-2.json").path
        XCTAssertNil(run(.pack(.install(path: path, confirmed: true))).failure)
        XCTAssertEqual(run(.pack(.install(path: path, confirmed: true))).failure,
                       CommandLineFailure(.dataError, "Pack 2 is already installed."))
        let noPack = run(.pack(.install(path: "-", confirmed: true)), input: Data("{}".utf8))
        XCTAssertEqual(noPack.failure?.exit, .dataError)
        XCTAssertEqual(try listed(), try releaseFixture(2).pack.indicators.map(\.name))
    }

    /// A file that can't be read exits 66 before the Security Extension is asked anything.
    func testAFileThatCannotBeReadExits66() {
        XCTAssertEqual(run(.pack(.install(path: "/nonexistent/pack.json", confirmed: true))).failure?.exit, .noInput)
    }

    /// Without `sudo`, where Settings lets `macmonitor` stream but not change the set, it's refused (77).
    func testWithoutPermissionToChangeTheSetItIsRefused() throws {
        let path = try fixtureURL("indicator-pack-2.json").path
        let refused = run(.pack(.install(path: path, confirmed: true)), grant: .streaming)
        XCTAssertEqual(refused.failure?.exit, .noPermission)
        XCTAssertEqual(try listed(), linked.map(\.name))
    }

    /// `indicators pack install [FILE|-] [--yes]` parses, takes one file at most and only `--yes`, and needs root.
    /// With no file it's the newest pack on GitHub.
    func testCommandLine() throws {
        XCTAssertEqual(try CommandLineParser.parse(["indicators", "pack", "install"]),
                       .indicators(.pack(.install(path: nil))))
        XCTAssertEqual(try CommandLineParser.parse(["indicators", "pack", "install", "pack.json"]),
                       .indicators(.pack(.install(path: "pack.json"))))
        let confirmed = try CommandLineParser.parse(["indicators", "pack", "install", "--yes", "-"])
        XCTAssertEqual(confirmed, .indicators(.pack(.install(path: "-", confirmed: true))))
        XCTAssertTrue(confirmed.requiresRoot)
        for arguments in [["indicators", "pack", "install", "a.json", "b.json"],
                          ["indicators", "pack", "install", "a.json", "--replace"],
                          ["indicators", "pack", "instal", "a.json"]] {
            XCTAssertThrowsError(try CommandLineParser.parse(arguments), arguments.joined(separator: " "))
        }
    }
}
