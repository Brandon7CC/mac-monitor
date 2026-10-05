//
//  ExecCommandLineTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Exec command line
/// Pins an exec event's `command_line` (Mac Monitor's addition): its arguments joined by spaces and trimmed, by
/// `ProcessExecEvent.enrich()`, exactly as the Security Extension used to build it by appending each argument after a
/// space.
final class ExecCommandLineTests: XCTestCase {
    /// The command line as the Security Extension built it before: each argument appended after a space, then the
    /// whole trimmed of whitespace.
    ///
    /// - Parameter args: The arguments.
    /// - Returns: The command line.
    private func concatenated(_ args: [String]) -> String {
        var commandLine = ""
        for arg in args {
            commandLine = "\(commandLine) \(arg)"
        }
        return commandLine.trimmingCharacters(in: .whitespaces)
    }
    
    /// The command line of an exec event with some arguments, as `enrich()` joins it.
    ///
    /// - Parameter args: The arguments.
    /// - Returns: The event's `command_line`.
    /// - Throws: The error reading the record, or an `XCTest` failure if the fixture has no process.
    private func joined(_ args: [String]) throws -> String? {
        var record = try fixtureObject("eslogger-exit.jsonl")
        let exec: [String: Any] = [
            "target": try XCTUnwrap(record["process"]), "script": NSNull(), "dyld_exec_path": "/bin/ls",
            "cwd": ["path": "/", "path_truncated": false, "stat": [:]], "last_fd": 2, "image_cputype": 16_777_228,
            "image_cpusubtype": 2, "args": args, "fds": [], "env": [],
        ]
        record["event"] = ["exec": exec]
        record["event_type"] = 9
        return try importRecord(record).event.exec?.command_line
    }
    
    /// No arguments, empty and whitespace-only ones (spaces, tabs, Unicode spaces), newlines, and Unicode.
    ///
    /// - Throws: The error reading a record.
    func testEdgeArgumentsMatchTheConcatenation() throws {
        let cases: [[String]] = [
            [], [""], ["", ""], [" "], [" ", " ", " "], ["\t", "ls"], ["ls", ""], ["ls", "", "-l"],
            ["ls", "-l", "/tmp"], ["  padded  ", "x  "], ["\u{00A0}", "nbsp\u{00A0}"], ["em\u{2003}", "\u{2003}"],
            ["new\nline", "\n"], ["\u{3000}ideographic", "\u{202F}"], ["ünïcödé", "😀", "a b"],
        ]
        for args in cases {
            XCTAssertEqual(try joined(args), concatenated(args), "\(args)")
        }
    }
    
    /// Random arguments drawn from letters, spaces of every kind, and line breaks.
    ///
    /// - Throws: The error reading a record.
    func testRandomArgumentsMatchTheConcatenation() throws {
        let alphabet: [Character] = ["a", "-", "/", " ", "\t", "\n", "\u{00A0}", "\u{2003}", "\u{3000}", "é", "😀"]
        for _ in 0..<200 {
            let args = (0..<Int.random(in: 0...6)).map { _ in
                String((0..<Int.random(in: 0...4)).map { _ in alphabet.randomElement()! })
            }
            XCTAssertEqual(try joined(args), concatenated(args), "\(args)")
        }
    }
}
