//
//  IndicatorPackUpdatesHeldBackTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/19/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Pack updates held back
/// Pins `macmonitor` while indicator pack updates wait for a later release (``IndicatorPackUpdates/isAvailable``):
/// `pack check`, `pack mode` and `pack install` with no file aren't commands, and nothing says an update mode, a last
/// look or a newer pack. A signed pack's file still installs, and `pack status` and `pack verify` still parse.
final class IndicatorPackUpdatesHeldBackTests: XCTestCase {
    /// Parse the arguments after `indicators pack`.
    ///
    /// - Parameter arguments: The arguments.
    /// - Returns: The command.
    /// - Throws: ``CommandLineUsageError`` for what isn't one.
    private func parse(_ arguments: String...) throws -> CommandLineInvocation {
        try CommandLineParser.parse(["indicators", "pack"] + arguments)
    }

    /// Updates are held back in a build as it ships.
    func testUpdatesAreHeldBack() {
        XCTAssertFalse(IndicatorPackUpdates.isAvailable)
        XCTAssertEqual(IndicatorPackInvocation.Name.offered, [.status, .install, .verify])
    }

    /// The commands that ask GitHub aren't commands, and the message that lists the commands leaves them out.
    func testTheGitHubCommandsAreNotCommands() throws {
        for arguments in [["check"], ["check", "--json"], ["mode", "off"], ["mode", "auto"], ["install"],
                          ["install", "--yes"]] {
            XCTAssertThrowsError(try CommandLineParser.parse(["indicators", "pack"] + arguments),
                                 arguments.joined(separator: " "))
        }
        XCTAssertThrowsError(try parse()) { error in
            XCTAssertEqual((error as? CommandLineUsageError)?.message,
                           "indicators pack needs status, install or verify.")
        }
        XCTAssertThrowsError(try parse("check")) { error in
            XCTAssertEqual((error as? CommandLineUsageError)?.message.hasPrefix("Unknown indicators pack command"),
                           true)
        }
    }

    /// A pack's file, the status and a verify still parse.
    func testTheFileCommandsStay() throws {
        XCTAssertEqual(try parse("status"), .indicators(.pack(.status())))
        XCTAssertEqual(try parse("install", "pack.json"), .indicators(.pack(.install(path: "pack.json"))))
        XCTAssertEqual(try parse("install", "-", "--yes"), .indicators(.pack(.install(path: "-", confirmed: true))))
        XCTAssertEqual(try parse("verify", "pack.json"), .indicators(.pack(.verify("pack.json"))))
    }

    /// `pack status` says only which pack this Mac has, as text and as JSON.
    func testStatusSaysOnlyThePack() throws {
        let savedMutes = SavedMuteSet(testing: try makeMuteStore())
        let savedIndicators = try makeSavedIndicatorSet(defaults: try linkedFixtures(), verifier: try packVerifier())
        let text = runIndicators(.pack(.status()), savedMutes: savedMutes, savedIndicators: savedIndicators,
                                 grant: .everything, confirm: { _ in nil })
        XCTAssertEqual(text.output, "Pack   this build's own\n")
        let json = runIndicators(.pack(.status(json: true)), savedMutes: savedMutes,
                                 savedIndicators: savedIndicators, grant: .everything, confirm: { _ in nil })
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.output.utf8)) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["pack", "source", "published", "commit", "linked", "needs_newer", "problem"])
    }

    /// `macmonitor status` says nothing of updates either.
    func testMacMonitorStatusSaysNothingOfUpdates() throws {
        let silent = StatusReport(tool: "3.2.0 (1)", app: nil, systemExtension: nil,
                                  answer: .failure(CommandLineFailure(.unavailable, "No answer.")))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(
            with: Data(StatusCommand.output(silent, json: true).utf8)) as? [String: [String: Any]])
        XCTAssertEqual(Set(object["indicators"]?.keys.map { $0 } ?? []), ["pack", "source", "published", "commit"])
    }
}
