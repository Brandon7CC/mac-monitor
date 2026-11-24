//
//  UpdateCommandTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/16/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - macmonitor update check
/// Pins `macmonitor update check`: its command line, what it says of a newer release and of none, its JSON, and its
/// exit status when the Security Extension can't say or GitHub couldn't be reached.
final class UpdateCommandTests: XCTestCase {
    /// A newer release, as the Security Extension reads it from GitHub.
    private static let release = UpdateDetails(version: "v3.2.1",
                                               downloadURL: URL(string: "https://example.com/Mac-Monitor.pkg")!,
                                               releaseNotes: "Notes.", releaseDate: "2026-11-21T10:00:00Z")

    /// A Security Extension's answer to an update check.
    ///
    /// - Parameters:
    ///   - update: What its look up found, or `nil` for a build that doesn't update itself.
    ///   - status: How the request went.
    /// - Returns: The reply.
    private func reply(_ update: UpdateCheck?, status: StreamReply.Status = .ok) -> StreamReply {
        StreamReply(status: status, sensorVersion: "3.2.0 (145)", update: update)
    }

    /// `update check` takes `--json` and nothing else, needs `check`, and needs no root.
    func testParsing() throws {
        XCTAssertEqual(try CommandLineParser.parse(["update", "check"]), .update(UpdateInvocation()))
        XCTAssertEqual(try CommandLineParser.parse(["update", "check", "--json"]),
                       .update(UpdateInvocation(json: true)))
        XCTAssertEqual(try CommandLineParser.parse(["update", "--help"]), .help(command: "update"))
        for arguments in [["update"], ["update", "install"], ["update", "check", "now"], ["update", "check", "--yes"]] {
            XCTAssertThrowsError(try CommandLineParser.parse(arguments), arguments.joined(separator: " "))
        }
        XCTAssertFalse(CommandLineCommand.update.requiresRoot)
        XCTAssertFalse(CommandLineInvocation.update(UpdateInvocation()).requiresRoot)
    }

    /// A newer release is said with its version, this Mac's, its page, and how to install it. None is said in a line.
    func testText() throws {
        let newer = try UpdateReport.read(.success(reply(.newer(Self.release)))).get()
        XCTAssertEqual(UpdateCommand.output(newer, json: false), """
            Mac Monitor 3.2.1 is out. This Mac has 3.2.0.
            https://github.com/Brandon7CC/mac-monitor/releases/tag/v3.2.1
            Open Mac Monitor and choose Check for Updates to install it.

            """)
        let latest = try UpdateReport.read(.success(reply(.upToDate))).get()
        XCTAssertEqual(latest, UpdateReport(available: false, current: "3.2.0"))
        XCTAssertEqual(UpdateCommand.output(latest, json: false), "Mac Monitor 3.2.0 is the latest release.\n")
    }

    /// `--json` writes every key, with `null` for what there isn't.
    func testJSON() throws {
        let newer = try UpdateReport.read(.success(reply(.newer(Self.release)))).get()
        XCTAssertEqual(UpdateCommand.output(newer, json: true), """
            {
              "available" : true,
              "current" : "3.2.0",
              "latest" : "3.2.1",
              "published" : "2026-11-21T10:00:00Z",
              "url" : "https://github.com/Brandon7CC/mac-monitor/releases/tag/v3.2.1"
            }

            """)
        let latest = try UpdateReport.read(.success(reply(.upToDate))).get()
        let object = try XCTUnwrap(JSONSerialization.jsonObject(
            with: Data(UpdateCommand.output(latest, json: true).utf8)) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["available", "current", "latest", "published", "url"])
        XCTAssertEqual(object["available"] as? Bool, false)
        XCTAssertTrue(object["latest"] is NSNull)
        XCTAssertTrue(object["url"] is NSNull)
    }

    /// It exits 75 when GitHub couldn't be reached, and 69 when the Security Extension doesn't check for updates, is
    /// older than `macmonitor`, or isn't there.
    func testFailures() {
        let failure = { (answer: Result<StreamReply, CommandLineFailure>) -> CommandLineFailure? in
            if case .failure(let failure) = UpdateReport.read(answer) { return failure }
            return nil
        }
        XCTAssertEqual(failure(.success(reply(.failed))), CommandLineFailure(.temporaryFailure, """
            GitHub couldn't be reached, or its answer couldn't be read. Try again later.
            """))
        XCTAssertEqual(failure(.success(reply(nil))), CommandLineFailure(.unavailable, """
            This Mac Monitor doesn't check for updates: it's a Community build.
            """))
        XCTAssertEqual(failure(.success(reply(nil, status: .unsupported)))?.exit, .unavailable)
        let older = StreamReply(status: .refused, problem: "Needs root.", sensorVersion: "3.1.0 (142)")
        XCTAssertEqual(failure(.success(older)), .olderSecurityExtension,
                       "One older than 3.2 refuses a request it doesn't know from a caller that may not stream")
        XCTAssertEqual(failure(.success(reply(nil, status: .refused)))?.exit, .noPermission)
        let gone = CommandLineFailure(.unavailable, "No answer.")
        XCTAssertEqual(failure(.failure(gone)), gone)
    }
}
