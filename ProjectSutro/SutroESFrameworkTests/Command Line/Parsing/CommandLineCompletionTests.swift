//
//  CommandLineCompletionTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/22/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Shell completion
/// Pins `macmonitor completion`: both scripts are valid for their shell, and bash's completes what the parser takes.
/// zsh's runs only inside zsh's completion system, so it's checked for syntax and content.
final class CommandLineCompletionTests: XCTestCase {
    /// Run a shell on a script.
    ///
    /// - Parameters:
    ///   - shell: The shell's path.
    ///   - arguments: Its arguments before the script's path.
    ///   - script: The script.
    /// - Returns: The exit status and standard output.
    /// - Throws: If the script can't be written or the shell can't run.
    private func run(_ shell: String, _ arguments: [String], script: String) throws -> (status: Int32, output: String) {
        let file = try temporaryFile(containing: script, named: "completion.sh")
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: shell)
        process.arguments = arguments + [file.path]
        process.standardOutput = pipe
        try process.run()
        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: output, as: UTF8.self))
    }

    /// What bash's script completes for a command line.
    ///
    /// - Parameter words: The words, the last being the one completed.
    /// - Returns: The completions, sorted.
    /// - Throws: If bash can't run.
    private func bashCompletions(_ words: String...) throws -> [String] {
        let quoted = words.map(CommandLineCompletion.quoted).joined(separator: " ")
        let script = CommandLineCompletion.script(for: .bash) + """
            COMP_WORDS=(\(quoted)); COMP_CWORD=\(words.count - 1); _macmonitor
            printf '%s\\n' "${COMPREPLY[@]}"
            """
        return try run("/bin/bash", [], script: script).output.split(separator: "\n").map(String.init).sorted()
    }

    /// Both scripts parse in their shell.
    func testTheScriptsAreValid() throws {
        XCTAssertEqual(try run("/bin/zsh", ["-n"], script: CommandLineCompletion.script(for: .zsh)).status, 0)
        XCTAssertEqual(try run("/bin/bash", ["-n"], script: CommandLineCompletion.script(for: .bash)).status, 0)
    }

    /// bash completes commands, options, option values, events and mute commands, and leaves paths to bash.
    func testBashCompletesWhatTheParserTakes() throws {
        XCTAssertEqual(try bashCompletions("macmonitor", "st"), ["stream"])
        XCTAssertEqual(try bashCompletions("macmonitor", "stream", "--f"), ["--for", "--format"])
        XCTAssertEqual(try bashCompletions("macmonitor", "stream", "--format", ""), ["jsonl", "pretty", "text"])
        XCTAssertEqual(try bashCompletions("macmonitor", "stream", "exe"), ["exec"])
        XCTAssertEqual(try bashCompletions("macmonitor", "stream", "--predicate", ""), [])
        XCTAssertEqual(try bashCompletions("macmonitor", "mute", "re"), ["remove", "reset"])
        XCTAssertEqual(try bashCompletions("macmonitor", "mute", "add", "/x", "--type", "target-"),
                       ["target-literal", "target-prefix"])
        XCTAssertEqual(try bashCompletions("macmonitor", "mute", "add", "--"), ["--event", "--type"])
        XCTAssertEqual(try bashCompletions("macmonitor", "mute", "add", "/us"), [], "bash completes the path")
        XCTAssertEqual(try bashCompletions("macmonitor", "completion", ""), ["bash", "zsh"])
    }

    /// zsh's script lists every command with its summary, every option, and every event.
    func testZshListsEverything() {
        let script = CommandLineCompletion.script(for: .zsh)
        XCTAssertTrue(script.hasPrefix("#compdef macmonitor\n"))
        for command in CommandLineCommand.allCases {
            XCTAssertTrue(script.contains(CommandLineCompletion.quoted("\(command.rawValue):\(command.help.summary)")))
        }
        for option in CommandLineOption.stream + CommandLineOption.validate {
            XCTAssertTrue(script.contains(" \(option.name)"), option.name)
        }
        XCTAssertTrue(script.contains("local -a events=(\(CommandLineCompletion.events))"))
        XCTAssertTrue(script.contains("'mute add')"))
    }
}
