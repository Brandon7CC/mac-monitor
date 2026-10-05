//
//  CommandLineParserTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Command line
/// Pins `macmonitor`'s command line: the defaults, event names, option syntax, help anywhere, and a usage error that
/// says what's wrong for everything else.
final class CommandLineParserTests: XCTestCase {
    /// Parse a command line written as one string.
    ///
    /// - Parameter line: The arguments, separated by spaces.
    /// - Returns: The invocation.
    /// - Throws: ``CommandLineUsageError``.
    private func parse(_ line: String) throws -> CommandLineInvocation {
        try CommandLineParser.parse(line.split(separator: " ").map(String.init))
    }
    
    /// Parse a stream command line.
    ///
    /// - Parameter line: The arguments after `stream`.
    /// - Returns: The stream, or the defaults after a test failure if it isn't one.
    /// - Throws: ``CommandLineUsageError``.
    private func stream(_ line: String) throws -> StreamInvocation {
        guard case .stream(let invocation) = try parse("stream " + line) else {
            XCTFail("'stream \(line)' isn't a stream.")
            return StreamInvocation()
        }
        return invocation
    }
    
    /// The usage error a command line gets.
    ///
    /// - Parameter line: The arguments.
    /// - Returns: The error's message, or `nil` if it parses.
    private func usageError(_ line: String) -> String? {
        do {
            _ = try parse(line)
            return nil
        } catch {
            return (error as? CommandLineUsageError)?.description
        }
    }
    
    /// `stream` alone: Mac Monitor's default events, the format by terminal, the saved mutes, no pipeline events.
    ///
    /// - Throws: ``CommandLineUsageError``.
    func testStreamDefaults() throws {
        let invocation = try stream("")
        XCTAssertEqual(invocation, StreamInvocation())
        XCTAssertEqual(invocation.events, [])
        XCTAssertNil(invocation.format)
        XCTAssertTrue(invocation.appliesSavedMutes)
        XCTAssertFalse(invocation.includeSelf)
        XCTAssertEqual(invocation.options, StreamOptions())
        XCTAssertEqual(invocation.resolvedFormat(isTerminal: true), .text)
        XCTAssertEqual(invocation.resolvedFormat(isTerminal: false), .jsonl)
        XCTAssertTrue(try parse("stream").requiresRoot)
    }
    
    /// Events by short name in any case or full name, each once in order; `all` is every supported event.
    ///
    /// - Throws: ``CommandLineUsageError``.
    func testEventNames() throws {
        XCTAssertEqual(try stream("exec FORK ES_EVENT_TYPE_NOTIFY_EXIT exec").events,
                       [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT])
        XCTAssertEqual(try stream("all").events, supportedEvents)
        XCTAssertEqual(try stream("exec all").events.count, supportedEvents.count)
        XCTAssertEqual(try stream("open").options.events, ["ES_EVENT_TYPE_NOTIFY_OPEN"])
    }
    
    /// AUTH, unmodeled, and unknown names are refused, pointing at `macmonitor events` only.
    func testEventsThatCantBeStreamed() {
        for name in ["ES_EVENT_TYPE_AUTH_EXEC", "auth_exec", "kextload", "nonsense", "ES_EVENT_TYPE_LAST"] {
            let message = usageError("stream \(name)")
            XCTAssertEqual(message, "'\(name)' isn't an event macmonitor can stream. Run 'macmonitor events' to list "
                                    + "them.", name)
        }
    }
    
    /// Options before or after events, `--format=` and `--format `, `--` before a name starting with a dash.
    ///
    /// - Throws: ``CommandLineUsageError``.
    func testOptionSyntax() throws {
        var expected = StreamInvocation()
        expected.events = [ES_EVENT_TYPE_NOTIFY_EXEC]
        expected.format = .jsonl
        expected.appliesSavedMutes = false
        expected.includeSelf = true
        for line in ["exec --format jsonl --no-mutes --include-self", "--format=jsonl --include-self exec --no-mutes",
                     "--no-mutes --include-self --format jsonl -- exec"] {
            XCTAssertEqual(try stream(line), expected, line)
        }
        XCTAssertEqual(try stream("--format text").format, .text)
        XCTAssertEqual(usageError("stream -- --no-mutes"),
                       "'--no-mutes' isn't an event macmonitor can stream. Run 'macmonitor events' to list them.")
    }
    
    /// Bad option values, missing values, values on flags, and unknown options are usage errors for `stream`.
    func testBadOptions() {
        XCTAssertEqual(usageError("stream --format xml"),
                       "--format must be text or jsonl, not 'xml'. Run 'macmonitor help stream'.")
        XCTAssertEqual(usageError("stream --format"), "--format needs a value. Run 'macmonitor help stream'.")
        XCTAssertEqual(usageError("stream --format --no-mutes"),
                       "--format needs a value. Run 'macmonitor help stream'.")
        XCTAssertEqual(usageError("stream --no-mutes=yes"), "--no-mutes takes no value. Run 'macmonitor help stream'.")
        XCTAssertEqual(usageError("stream --pid 7"), "Unknown option '--pid' for stream. Run 'macmonitor help stream'.")
        XCTAssertEqual(usageError("stream -x"), "Unknown option '-x' for stream. Run 'macmonitor help stream'.")
    }
    
    /// `-h` or `--help` anywhere before `--` asks for the command's help, `help`'s included; no arguments, `help`,
    /// `-h` and `--help` alone ask for the overview.
    ///
    /// - Throws: ``CommandLineUsageError``.
    func testHelp() throws {
        XCTAssertEqual(try parse(""), .help(command: nil))
        XCTAssertEqual(try parse("help"), .help(command: nil))
        XCTAssertEqual(try parse("-h"), .help(command: nil))
        XCTAssertEqual(try parse("--help"), .help(command: nil))
        XCTAssertEqual(try parse("help stream"), .help(command: "stream"))
        XCTAssertEqual(try parse("stream exec --format nope -h"), .help(command: "stream"))
        XCTAssertEqual(try parse("events --help"), .help(command: "events"))
        for line in ["help -h", "help --help", "help stream -h", "help -h stream"] {
            XCTAssertEqual(try parse(line), .help(command: "help"), line)
        }
        XCTAssertNil(usageError("help help"))
        XCTAssertEqual(usageError("help nope"), "Unknown command 'nope'. Run 'macmonitor help'.")
        XCTAssertEqual(usageError("help stream events"), "help takes one command at most. Run 'macmonitor help help'.")
        XCTAssertFalse(try parse("help").requiresRoot)
    }
    
    /// `version`, `--version`, and `events` need no root and take no arguments; unknown commands and options are
    /// usage errors.
    ///
    /// - Throws: ``CommandLineUsageError``.
    func testOtherCommands() throws {
        XCTAssertEqual(try parse("version"), .version)
        XCTAssertEqual(try parse("--version"), .version)
        XCTAssertEqual(try parse("events"), .events)
        XCTAssertFalse(try parse("version").requiresRoot)
        XCTAssertFalse(try parse("events").requiresRoot)
        XCTAssertEqual(usageError("events exec"),
                       "events takes no arguments, not 'exec'. Run 'macmonitor help events'.")
        XCTAssertEqual(usageError("version --verbose"),
                       "version takes no arguments, not '--verbose'. Run 'macmonitor help version'.")
        XCTAssertEqual(usageError("stram"), "Unknown command 'stram'. Run 'macmonitor help'.")
        XCTAssertEqual(usageError("--verbose"), "Unknown option '--verbose'. Run 'macmonitor help'.")
    }
    
    /// Help describes every command once, every command parses as itself, and the overview names the commands that
    /// need root.
    ///
    /// - Throws: ``CommandLineUsageError``.
    func testTheHelpMatchesTheCommands() throws {
        XCTAssertEqual(CommandLineHelp.commands.map(\.id).sorted { $0.rawValue < $1.rawValue },
                       CommandLineCommand.Name.allCases.sorted { $0.rawValue < $1.rawValue })
        XCTAssertTrue(CommandLineHelp.text(for: nil).contains(" stream and mute need root: run them with sudo."))
        for command in CommandLineHelp.commands {
            let invocation = try parse(command.id == .mute ? "mute list" : command.name)
            XCTAssertEqual(invocation.id, command.id)
            XCTAssertEqual(invocation.command, command.name)
            XCTAssertTrue(CommandLineHelp.text(for: command.name).hasPrefix("Usage: \(command.usage)\n"))
            XCTAssertTrue(CommandLineHelp.text(for: nil).contains("  \(command.name)"))
        }
    }
    
    /// `events` lists every supported event once, by short and full name, with the defaults marked.
    func testTheEventList() {
        let lines = CommandLineHelp.eventList().split(separator: "\n")
        XCTAssertEqual(lines.count, supportedEvents.count)
        XCTAssertTrue(lines.contains { $0.hasPrefix("* exec ") && $0.hasSuffix(" ES_EVENT_TYPE_NOTIFY_EXEC") })
        XCTAssertTrue(lines.contains { $0.hasPrefix("  open ") && $0.hasSuffix(" ES_EVENT_TYPE_NOTIFY_OPEN") })
        XCTAssertEqual(lines.filter { $0.hasPrefix("*") }.count, Set(defaultEventSubscriptions.map(\.rawValue)).count)
    }
}
