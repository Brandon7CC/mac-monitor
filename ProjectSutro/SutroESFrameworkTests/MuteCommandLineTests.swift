//
//  MuteCommandLineTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Mute command lines
/// Pins `macmonitor mute`'s command line: every subcommand, the narrowest type by default, event names, and a usage
/// error that says what's wrong for everything else: 64 for a command line that can't be read, 65 for a mute that
/// can't be used.
final class MuteCommandLineTests: XCTestCase {
    /// Parse a mute command line.
    ///
    /// - Parameter line: The arguments after `mute`, separated by spaces.
    /// - Returns: The invocation.
    /// - Throws: ``CommandLineUsageError``.
    private func parse(_ line: String) throws -> CommandLineInvocation {
        try CommandLineParser.parse(["mute"] + line.split(separator: " ").map(String.init))
    }
    
    /// The usage error a mute command line gets.
    ///
    /// - Parameter line: The arguments after `mute`.
    /// - Returns: The error's message, or `nil` if it parses.
    private func usageError(_ line: String) -> String? {
        do {
            _ = try parse(line)
            return nil
        } catch {
            return (error as? CommandLineUsageError)?.message
        }
    }
    
    /// How `macmonitor` exits for a mute command line it can't act on.
    ///
    /// - Parameter line: The arguments after `mute`.
    /// - Returns: The exit status, or `nil` if it parses.
    private func exitStatus(_ line: String) -> CommandLineExit? {
        do {
            _ = try parse(line)
            return nil
        } catch {
            return CommandLineFailure.parsing(error).exit
        }
    }
    
    /// `export` takes nothing, `list` only its format, and `reset` only `--yes`; every mute command needs root.
    ///
    /// - Throws: ``CommandLineUsageError``.
    func testCommandsWithoutArguments() throws {
        XCTAssertEqual(try parse("list"), .mute(.list(format: .text)))
        XCTAssertEqual(try parse("list --format json"), .mute(.list(format: .json)))
        XCTAssertEqual(try parse("list --format=text"), .mute(.list(format: .text)))
        XCTAssertEqual(try parse("export"), .mute(.export))
        XCTAssertEqual(try parse("reset"), .mute(.reset(confirmed: false)))
        XCTAssertEqual(try parse("reset --yes"), .mute(.reset(confirmed: true)))
        XCTAssertEqual(usageError("reset now"), "mute reset takes no arguments, not 'now'.")
        XCTAssertEqual(usageError("reset --yes=no"), "--yes takes no value.")
        XCTAssertEqual(usageError("reset --merge"), "Unknown option '--merge' for mute reset.")
        XCTAssertTrue(try parse("list").requiresRoot)
        XCTAssertEqual(usageError("list all"), "mute list takes no arguments, not 'all'.")
        XCTAssertEqual(usageError("list --format jsonl"), "--format must be text or json, not 'jsonl'.")
        XCTAssertEqual(usageError("list --merge"), "Unknown option '--merge' for mute list.")
        XCTAssertEqual(usageError("export --format json"), "mute export takes no arguments, not '--format'.")
        XCTAssertEqual(usageError(""), "mute needs one of list, add, remove, import, export or reset.")
        XCTAssertEqual(usageError("clear"), "Unknown mute command 'clear'.")
    }
    
    /// `add` and `remove`: a path, literal unless a type is given (by short or full name), and events by short or full
    /// name, any NOTIFY event Mac Monitor knows.
    ///
    /// - Throws: ``CommandLineUsageError``.
    func testAddAndRemove() throws {
        XCTAssertEqual(try parse("add /usr/bin/yes"),
                       .mute(.add(MuteFile.Entry(path: "/usr/bin/yes", type: "ES_MUTE_PATH_TYPE_LITERAL"))))
        XCTAssertEqual(try parse("remove --type prefix /Library/ --event exec --event=ES_EVENT_TYPE_NOTIFY_OPEN"),
                       .mute(.remove(MuteFile.Entry(path: "/Library/", type: "ES_MUTE_PATH_TYPE_PREFIX",
                                                    events: ["ES_EVENT_TYPE_NOTIFY_EXEC",
                                                             "ES_EVENT_TYPE_NOTIFY_OPEN"]))))
        XCTAssertEqual(try parse("add /x --type ES_MUTE_PATH_TYPE_TARGET_LITERAL --event lookup"),
                       .mute(.add(MuteFile.Entry(path: "/x", type: "ES_MUTE_PATH_TYPE_TARGET_LITERAL",
                                                 events: ["ES_EVENT_TYPE_NOTIFY_LOOKUP"]))))
        XCTAssertEqual(try parse("add /x --type target-prefix"),
                       .mute(.add(MuteFile.Entry(path: "/x", type: "ES_MUTE_PATH_TYPE_TARGET_PREFIX"))))
        XCTAssertEqual(try parse("add /x -h"), .help(command: "mute"))
    }
    
    /// What `add` and `remove` refuse: a mute that can't be used exits 65, as the Security Extension's refusal of one
    /// does; a command line that can't be read exits 64.
    func testBadEntries() {
        XCTAssertEqual(usageError("add"), "mute add needs a path.")
        XCTAssertEqual(usageError("add usr/bin/yes"), "'usr/bin/yes' isn't an absolute path.")
        XCTAssertEqual(usageError("remove /a /b"), "mute remove takes one path, not also '/b'.")
        XCTAssertEqual(usageError("add /a --type folder"),
                       "--type must be literal, prefix, target-literal or target-prefix, not 'folder'.")
        XCTAssertEqual(usageError("add /a --event auth_exec"), "'auth_exec' isn't a NOTIFY event Mac Monitor knows.")
        XCTAssertEqual(usageError("add /a --event"), "--event needs a value.")
        XCTAssertEqual(usageError("add /a --all"), "Unknown option '--all' for mute add.")
        
        for line in ["add usr/bin/yes", "remove relative/path --event exec", "add /a --type folder",
                     "remove /a --event auth_exec", "add /a --event nope"] {
            XCTAssertEqual(exitStatus(line), .dataError, line)
        }
        for line in ["add", "remove /a /b", "add /a --event", "add /a --all", "add --type", "list --format jsonl",
                     "clear", ""] {
            XCTAssertEqual(exitStatus(line), .usage, line)
        }
    }
    
    /// `import FILE|- [--merge] [--yes]`.
    ///
    /// - Throws: ``CommandLineUsageError``.
    func testImport() throws {
        XCTAssertEqual(try parse("import mutes.json"),
                       .mute(.importFile(path: "mutes.json", merge: false, confirmed: false)))
        XCTAssertEqual(try parse("import --merge -"), .mute(.importFile(path: "-", merge: true, confirmed: false)))
        XCTAssertEqual(try parse("import --yes mutes.json --merge"),
                       .mute(.importFile(path: "mutes.json", merge: true, confirmed: true)))
        XCTAssertEqual(usageError("import a --merge=1"), "--merge takes no value.")
        XCTAssertEqual(usageError("import"), "mute import needs a file, or - for standard input.")
        XCTAssertEqual(usageError("import a b"), "mute import takes one file, not also 'b'.")
        XCTAssertEqual(usageError("import a --replace"), "Unknown option '--replace' for mute import.")
    }
}
