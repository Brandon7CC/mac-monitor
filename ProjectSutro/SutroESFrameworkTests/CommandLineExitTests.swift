//
//  CommandLineExitTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Exit statuses
/// Pins what `macmonitor` tells the user and how it exits for every answer the Security Extension can give and every
/// way the connection can fail.
final class CommandLineExitTests: XCTestCase {
    /// Every reply status maps to its exit status; only `ok` is no failure, and the Security Extension's own words
    /// are kept where they're the clearest.
    func testEveryReplyStatus() {
        let expected: [(StreamReply.Status, CommandLineExit?)] = [
            (.ok, nil), (.invalid, .usage), (.unsupported, .unavailable), (.refused, .noPermission),
            (.alreadyStreaming, .software), (.sessionLimit, .temporaryFailure), (.clientLimit, .temporaryFailure),
            (.notPermitted, .unavailable), (.failed, .unavailable)
        ]
        for (status, exit) in expected {
            let failure = CommandLineFailure.reply(StreamReply(status, problem: "Because.", sensorVersion: "2.1.0 (9)"))
            XCTAssertEqual(failure?.exit, exit, status.rawValue)
        }
        XCTAssertEqual(CommandLineFailure.reply(StreamReply(.sessionLimit, problem: "3 are running.",
                                                            sensorVersion: "2.2.0 (1)"))?.message, "3 are running.")
        let older = CommandLineFailure.reply(StreamReply(.unsupported, sensorVersion: "2.1.0 (9)"))
        XCTAssertEqual(older?.message, """
            The Security Extension (2.1.0 (9)) is older than macmonitor. Open Mac Monitor to finish updating its \
            Security Extension.
            """)
    }
    
    /// Every mute reply status maps to its exit status, as the README lists them; the Security Extension's own words
    /// are kept, and a reply without any still says what happened.
    func testEveryMuteReplyStatus() {
        let expected: [(MuteReply.Status, CommandLineExit?)] = [
            (.ok, nil), (.refused, .noPermission), (.notAdministrator, .noPermission), (.invalid, .dataError),
            (.storageFailed, .ioError), (.readOnly, .unavailable), (.unsupported, .unavailable)
        ]
        for (status, exit) in expected {
            let worded = CommandLineFailure.reply(MuteReply(status: status, mutes: [], problems: ["Because.", "So."]))
            XCTAssertEqual(worded?.exit, exit, status.rawValue)
            let bare = CommandLineFailure.reply(MuteReply(status: status, mutes: []))
            XCTAssertEqual(bare?.exit, exit, status.rawValue)
            XCTAssertFalse(bare?.message.isEmpty ?? false, status.rawValue)
            guard status != .ok, status != .unsupported else { continue }
            XCTAssertEqual(worded?.message, "Because. So.", status.rawValue)
        }
    }
    
    /// A command line that can't be read exits 64, or 65 when it names a mute that can't be used, and says what's
    /// wrong and where to read more, as `macmonitor` always has.
    func testParsingErrors() {
        let relative = CommandLineFailure.parsing(CommandLineUsageError.unusableMute("'a' isn't an absolute path."))
        XCTAssertEqual(relative.exit, .dataError)
        XCTAssertEqual(relative.description, "macmonitor: 'a' isn't an absolute path. Run 'macmonitor help mute'.")
        let unknown = CommandLineFailure.parsing(CommandLineUsageError("Unknown command 'x'."))
        XCTAssertEqual(unknown.exit, .usage)
        XCTAssertEqual(unknown.description, "macmonitor: Unknown command 'x'. Run 'macmonitor help'.")
        XCTAssertEqual(CommandLineFailure.parsing(CocoaError(.fileReadUnknown)).exit, .usage)
    }
    
    /// XPC errors before the first answer tell "not running" from "refused" from "wrong signature"; after it, the
    /// Security Extension stopped. Every connection failure exits 69.
    func testConnectionErrors() {
        func failure(_ code: Int, started: Bool, domain: String = NSCocoaErrorDomain) -> CommandLineFailure {
            CommandLineFailure.connection(NSError(domain: domain, code: code), started: started)
        }
        XCTAssertTrue(failure(4099, started: false).message.hasPrefix("Mac Monitor's Security Extension isn't running"))
        XCTAssertTrue(failure(4097, started: false).message.hasPrefix("The Security Extension refused macmonitor."))
        XCTAssertTrue(failure(4102, started: false).message.contains("code signature didn't match"))
        XCTAssertTrue(failure(4102, started: true).message.contains("code signature didn't match"))
        XCTAssertEqual(failure(4097, started: true), .stopped)
        XCTAssertEqual(failure(4099, started: true), .stopped)
        XCTAssertTrue(failure(4097, started: false, domain: "Other").message.hasPrefix("Couldn't reach"))
        for code in [4097, 4099, 4102, 1] {
            XCTAssertEqual(failure(code, started: false).exit, .unavailable)
        }
    }
    
    /// A root-only command without root exits 77 and says how to run the same command line with sudo, quoting what
    /// a shell would split or expand.
    func testNotRoot() {
        let failure = CommandLineFailure.notRoot("mute", arguments: ["mute", "list"])
        XCTAssertEqual(failure.exit, .noPermission)
        XCTAssertEqual(failure.description, "macmonitor: 'mute' needs root: sudo macmonitor mute list")
        XCTAssertEqual(CommandLineFailure.notRoot("stream", arguments: ["stream", "exec", "fork", "--format=jsonl"])
                        .message, "'stream' needs root: sudo macmonitor stream exec fork --format=jsonl")
        XCTAssertEqual(CommandLineFailure.notRoot("mute", arguments: ["mute", "add", "/Users/b/It's mine", "--type",
                                                                      "prefix", "--event", "$HOME", ""]).message,
                       #"'mute' needs root: sudo macmonitor mute add '/Users/b/It'\''s mine' --type prefix --event "#
                        + #"'$HOME' ''"#)
        XCTAssertEqual(CommandLineExit.noPermission.rawValue, 77)
        XCTAssertEqual(CommandLineExit.usage.rawValue, 64)
        XCTAssertEqual(CommandLineExit.temporaryFailure.rawValue, 75)
    }
}
