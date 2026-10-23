//
//  CommandLineSuggestionTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/22/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Suggestions
/// Pins "Did you mean …?": a typo of a command, option, event or shell gets the name meant, anything further off gets
/// none, and every option a suggestion or completion offers is one the parser takes.
final class CommandLineSuggestionTests: XCTestCase {
    /// The usage error a command line gets.
    ///
    /// - Parameter arguments: The arguments.
    /// - Returns: The error's message, or `nil` if it parses.
    private func usageError(_ arguments: String...) -> String? {
        do {
            _ = try CommandLineParser.parse(arguments)
            return nil
        } catch {
            return (error as? CommandLineUsageError)?.description
        }
    }

    /// Insertions, deletions, changes and swaps of neighbors each count one edit.
    func testDistance() {
        let pairs: [(String, String, Int)] = [("stream", "stream", 0), ("strem", "stream", 1), ("exce", "exec", 1),
                                              ("--fromat", "--format", 1), ("opne", "open", 1), ("", "abc", 3),
                                              ("kitten", "sitting", 3)]
        for (a, b, edits) in pairs {
            XCTAssertEqual(CommandLineSuggestion.distance(Array(a), Array(b)), edits, "\(a) \(b)")
        }
        XCTAssertEqual(CommandLineSuggestion.closest(to: "EXCE", among: ["exec", "exit"]), "exec")
        XCTAssertNil(CommandLineSuggestion.closest(to: "xyz", among: ["exec", "exit"]))
        XCTAssertNil(CommandLineSuggestion.closest(to: "ex", among: ["exec"]), "Two edits is too far for two letters")
    }

    /// Every kind of name that can be mistyped gets a suggestion.
    func testEachMistakeSuggestsTheNameMeant() {
        XCTAssertEqual(usageError("strem"), "Unknown command 'strem'. Did you mean 'stream'? Run 'macmonitor help'.")
        XCTAssertEqual(usageError("--verison"),
                       "Unknown option '--verison'. Did you mean '--version'? Run 'macmonitor help'.")
        XCTAssertEqual(usageError("stream", "--fromat", "json"), "Unknown option '--fromat' for stream. Did you mean "
                       + "'--format'? Run 'macmonitor help stream'.")
        XCTAssertEqual(usageError("stream", "--signing-ids", "x"), "Unknown option '--signing-ids' for stream. Did "
                       + "you mean '--signing-id'? Run 'macmonitor help stream'.")
        XCTAssertEqual(usageError("stream", "exce"), "'exce' isn't an event macmonitor can stream. Did you mean "
                       + "'exec'? Run 'macmonitor events' to list them.")
        XCTAssertEqual(usageError("stream", "ES_EVENT_TYPE_NOTIFY_EXCE"), "'ES_EVENT_TYPE_NOTIFY_EXCE' isn't an "
                       + "event macmonitor can stream. Did you mean 'ES_EVENT_TYPE_NOTIFY_EXEC'? Run 'macmonitor "
                       + "events' to list them.")
        XCTAssertEqual(usageError("mute", "lsit"),
                       "Unknown mute command 'lsit'. Did you mean 'list'? Run 'macmonitor help mute'.")
        XCTAssertEqual(usageError("mute", "add", "/x", "--tpye", "prefix"), "Unknown option '--tpye' for mute add. "
                       + "Did you mean '--type'? Run 'macmonitor help mute'.")
        XCTAssertEqual(usageError("mute", "reset", "--yse"),
                       "Unknown option '--yse' for mute reset. Did you mean '--yes'? Run 'macmonitor help mute'.")
        XCTAssertEqual(usageError("mute", "add", "/x", "--event", "opne"), "'opne' isn't a NOTIFY event Mac Monitor "
                       + "knows. Did you mean 'open'? Run 'macmonitor help mute'.")
        XCTAssertEqual(usageError("validate", "--esloger", "t.jsonl"), "Unknown option '--esloger' for validate. "
                       + "Did you mean '--eslogger'? Run 'macmonitor help validate'.")
        XCTAssertEqual(usageError("help", "evnets"),
                       "Unknown command 'evnets'. Did you mean 'events'? Run 'macmonitor help'.")
        XCTAssertEqual(usageError("completion", "zhs"), "macmonitor has no completion for 'zhs'. Did you mean "
                       + "'zsh'? Run 'macmonitor help completion'.")
        XCTAssertEqual(usageError("stream", "--nonsense"),
                       "Unknown option '--nonsense' for stream. Run 'macmonitor help stream'.")
    }

    /// Every option suggestions and completion offer parses, with a value of the kind it says it takes.
    func testEveryListedOptionParses() throws {
        let texts = ["--for": "30s", "--count": "10", "--pid": "1", "--predicate": "event_type == 9"]
        /// An option and a value of its kind.
        func arguments(_ option: CommandLineOption) -> [String] {
            switch option.value {
            case .none: return [option.name]
            case .choice(let words): return [option.name, words[0]]
            case .event: return [option.name, "exec"]
            case .file: return [option.name, "/tmp/file"]
            case .text: return [option.name, texts[option.name] ?? "x"]
            }
        }
        for option in CommandLineOption.stream {
            XCTAssertNoThrow(try CommandLineParser.parse(["stream"] + arguments(option)), option.name)
        }
        for option in CommandLineOption.validate {
            XCTAssertNoThrow(try CommandLineParser.parse(["validate"] + arguments(option) + ["t.jsonl"]), option.name)
        }
        let operands: [MuteInvocation.Name: [String]] = [.add: ["/x"], .remove: ["/x"], .import: ["file.json"]]
        for name in MuteInvocation.Name.allCases {
            for option in CommandLineOption.mute(name) {
                let line = ["mute", name.rawValue] + arguments(option) + (operands[name] ?? [])
                XCTAssertNoThrow(try CommandLineParser.parse(line), line.joined(separator: " "))
            }
        }
    }
}
