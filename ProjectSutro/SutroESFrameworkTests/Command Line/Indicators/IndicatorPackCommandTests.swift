//
//  IndicatorPackCommandTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/16/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Looking for a pack from the command line
/// Pins `macmonitor indicators pack status`, `check`, `mode`, and `install` with no file: what each says of the pack
/// this Mac has and of a newer one on GitHub, its JSON, and its exit status when GitHub can't be reached. GitHub is a
/// ``FakePackFetcher``, and the build links in ``XCTestCase/linkedFixtures()``.
final class IndicatorPackCommandTests: XCTestCase {
    private var savedMutes = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))
    private var savedIndicators: SavedIndicatorSet?
    private var github = FakePackFetcher()

    /// Pack updates are on for these tests, and held back again after each (``IndicatorPackUpdates/isAvailable``).
    override func tearDown() {
        IndicatorPackUpdates.isAvailable = false
        super.tearDown()
    }

    /// A mute set, and an indicator set that trusts the fixtures' signer and asks the test's GitHub.
    ///
    /// - Throws: If a directory can't be created or a fixture is missing.
    override func setUpWithError() throws {
        try super.setUpWithError()
        IndicatorPackUpdates.isAvailable = true
        savedMutes = SavedMuteSet(testing: try makeMuteStore())
        github = FakePackFetcher()
        savedIndicators = try makeSavedIndicatorSet(defaults: try linkedFixtures(), verifier: try packVerifier(),
                                                    fetcher: github, clock: { XCTestCase.packClock })
    }

    /// Run one indicators command against this test's sets and wait for it.
    ///
    /// - Parameters:
    ///   - invocation: The command.
    ///   - grant: What the caller may do: everything, as root may.
    ///   - confirm: Answers the question it asks: by default there's no one to ask.
    /// - Returns: What it did.
    private func run(_ invocation: IndicatorPackInvocation, grant: CommandLineGrant = .everything,
                     confirm: @escaping (String) -> Bool? = { _ in nil }) -> IndicatorRun {
        runIndicators(.pack(invocation), savedMutes: savedMutes, savedIndicators: savedIndicators!, grant: grant,
                      confirm: confirm)
    }

    /// A command's JSON, read.
    ///
    /// - Parameter run: What the command did.
    /// - Returns: The object it wrote.
    /// - Throws: A failure when it didn't write one.
    private func object(_ run: IndicatorRun) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(run.output.utf8)) as? [String: Any], run.output)
    }

    /// `status` says which pack this Mac has, the mode, and what the last look found, and asks GitHub nothing.
    func testStatus() throws {
        XCTAssertEqual(run(.status()).output, """
            Pack           this build's own
            Updates        notify
            Last checked   never
            Available      none

            """)
        github.offer([("pack-3", try releaseFixture(3).file)])
        XCTAssertNil(run(.check()).failure)
        let asked = github.asked.count
        XCTAssertEqual(run(.status()).output, """
            Pack           this build's own
            Updates        notify
            Last checked   2026-11-15T12:00:00Z
            Available      pack 3

            """)
        XCTAssertNil(run(.install(path: nil, confirmed: true)).failure)
        XCTAssertEqual(run(.status()).output, """
            Pack           3, installed
            Published      2026-11-16T00:00:00Z
            Commit         3333333
            Not run        1 that need a newer Mac Monitor
            Updates        notify
            Last checked   2026-11-15T12:00:00Z
            Available      none

            """)
        let json = try object(run(.status(json: true)))
        XCTAssertEqual(Set(json.keys), ["pack", "source", "published", "commit", "linked", "needs_newer", "mode",
                                        "checked", "available", "problem"])
        XCTAssertEqual(json["pack"] as? Int, 3)
        XCTAssertEqual(json["source"] as? String, "installed")
        XCTAssertEqual(json["mode"] as? String, "notify")
        XCTAssertTrue(json["available"] is NSNull)
        XCTAssertTrue(json["problem"] is NSNull)
        XCTAssertEqual(github.asked.count, asked, "The install used what the check fetched, and status asked nothing")
    }

    /// `check` says a newer pack is out, what installing it would change and how to install it, or that there's
    /// none. It installs nothing.
    func testCheck() throws {
        github.offer([])
        XCTAssertEqual(run(.check()).output, """
            There's no newer indicator pack. This Mac has this build's own indicators.

            """)
        let none = try object(run(.check(json: true)))
        XCTAssertEqual(none["available"] as? Bool, false)
        XCTAssertTrue(none["latest"] is NSNull)
        XCTAssertEqual(none["current"] as? Int, 0)

        savedIndicators?.queue.sync { savedIndicators?.lastFetch = nil }
        github.offer([("pack-2", try releaseFixture(2).file)])
        XCTAssertEqual(run(.check()).output, """
            Indicator pack 2 is out. This Mac has this build's own indicators.
            It adds 1 indicator, removes 1 and changes 1: 3 indicators now, 3 after.
            Of Mac Monitor's own indicators, it removes 1 (“Fixture dropped”) and replaces 1 (“Fixture program \
            ran”).
            Install it with 'sudo macmonitor indicators pack install'.

            """)
        let newer = try object(run(.check(json: true)))
        XCTAssertEqual(newer["available"] as? Bool, true)
        XCTAssertEqual(newer["latest"] as? Int, 2)
        XCTAssertEqual(newer["added"] as? Int, 1)
        XCTAssertEqual(newer["removed"] as? Int, 1)
        XCTAssertEqual(newer["changed"] as? Int, 1)
        XCTAssertEqual(run(.status()).output.contains("Pack           this build's own"), true)
    }

    /// `install` with no file asks first, installs the newest pack from GitHub, and says there's none when there
    /// isn't.
    func testInstallTheNewest() throws {
        github.offer([("pack-2", try releaseFixture(2).file)])
        XCTAssertEqual(run(.install(path: nil)).failure?.exit, .usage, "No terminal to ask at")
        let questions = DiagnosticLines()
        let installed = run(.install(path: nil)) { questions.append($0); return true }
        XCTAssertEqual(installed.output, "Installed indicator pack 2 from GitHub: 3 indicators now.\n")
        XCTAssertEqual(questions.all.first?.hasPrefix("Install indicator pack 2 from GitHub?\n"), true)
        for confirmed in [false, true] {
            let again = run(.install(path: nil, confirmed: confirmed)) { _ in
                XCTFail("Nothing to ask about")
                return false
            }
            XCTAssertNil(again.failure)
            XCTAssertEqual(again.output, "There's no newer indicator pack. This Mac has pack 2, installed.\n")
        }
    }

    /// A check waits for the Security Extension to ask GitHub, longer than it waits for any other answer.
    func testACheckWaitsForGitHub() throws {
        github.offer([("pack-2", try releaseFixture(2).file)])
        github.hold()
        let github = github
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.6) { github.release() }
        let slow = runIndicators(.pack(.check()), savedMutes: savedMutes, savedIndicators: savedIndicators!,
                                 timeout: .milliseconds(150))
        XCTAssertNil(slow.failure)
        XCTAssertTrue(slow.output.hasPrefix("Indicator pack 2 is out."), slow.output)
    }

    /// What's installed is the release that was asked about. When a later one comes out while the question waits,
    /// nothing is installed, and it says to check again.
    func testOnlyTheReleaseAskedAboutIsInstalled() throws {
        github.offer([("pack-2", try releaseFixture(2).file)])
        let later = [("pack-3", try releaseFixture(3).file)]
        let set = savedIndicators!, github = github
        let overtaken = run(.install(path: nil)) { _ in
            github.offer(later)
            set.queue.sync { set.lastFetch = nil }
            return true
        }
        XCTAssertEqual(overtaken.failure, CommandLineFailure(.dataError, """
            Pack 3 is out now, not pack 2, which was checked. Check again before installing.
            """))
        XCTAssertTrue(run(.status()).output.contains("Pack           this build's own\n"))
        XCTAssertTrue(run(.status()).output.contains("Available      pack 3\n"))
    }

    /// GitHub not answering exits 75 with the reason, for a check and an install.
    func testGitHubNotAnsweringExits75() {
        github.answer(IndicatorPackRelease.releasesURL, with: .failure(.unreachable("Offline.")))
        for invocation in [IndicatorPackInvocation.check(), .install(path: nil, confirmed: true),
                           .install(path: nil)] {
            XCTAssertEqual(run(invocation, confirm: { _ in true }).failure,
                           CommandLineFailure(.temporaryFailure, "GitHub couldn't be reached. Offline."))
        }
        XCTAssertTrue(run(.status()).output.contains("Problem        GitHub couldn't be reached. Offline.\n"))
    }

    /// `mode` sets what the Security Extension does about newer packs, and needs permission to change the set.
    func testMode() {
        XCTAssertEqual(run(.mode(.automatic)).output, "Indicator pack updates are set to auto.\n")
        XCTAssertTrue(run(.status()).output.contains("Updates        auto\n"))
        XCTAssertEqual(run(.mode(.off), grant: .streaming).failure?.exit, .noPermission)
        XCTAssertEqual(run(.mode(.off)).output, "Indicator pack updates are set to off.\n")
        XCTAssertEqual(run(.check(), grant: .streaming).failure?.exit, .noPermission, "Off: GitHub isn't asked")
        XCTAssertEqual(github.asked, [])
    }

    /// Each command parses, takes only its own options, and needs root.
    func testCommandLine() throws {
        let lines: [([String], IndicatorPackInvocation)] = [
            (["status"], .status()), (["status", "--json"], .status(json: true)), (["check"], .check()),
            (["check", "--json"], .check(json: true)), (["mode", "off"], .mode(.off)),
            (["mode", "notify"], .mode(.notify)), (["mode", "auto"], .mode(.automatic)),
        ]
        for (arguments, invocation) in lines {
            let parsed = try CommandLineParser.parse(["indicators", "pack"] + arguments)
            XCTAssertEqual(parsed, .indicators(.pack(invocation)), arguments.joined(separator: " "))
            XCTAssertTrue(parsed.requiresRoot)
        }
        for arguments in [["status", "now"], ["status", "--yes"], ["check", "--yes"], ["check", "pack.json"],
                          ["mode"], ["mode", "automatic"], ["mode", "off", "--json"], ["mode", "off", "notify"]] {
            XCTAssertThrowsError(try CommandLineParser.parse(["indicators", "pack"] + arguments),
                                 arguments.joined(separator: " "))
        }
    }
}
