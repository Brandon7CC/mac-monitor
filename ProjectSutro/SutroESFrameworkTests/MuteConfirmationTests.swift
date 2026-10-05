//
//  MuteConfirmationTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Asking before a change
/// Pins the question `macmonitor mute import` and `mute reset` ask: what it says a change does to the saved set, and
/// which answers are yes.
final class MuteConfirmationTests: XCTestCase {
    /// Ask with an answer already typed, over pipes.
    ///
    /// - Parameter answer: What's typed, newline included.
    /// - Returns: The answer as read, what was written as the question, and what was left unread.
    /// - Throws: The error closing a pipe.
    private func ask(typing answer: String) throws -> (isYes: Bool, question: String, unread: String) {
        let (input, output) = (Pipe(), Pipe())
        input.fileHandleForWriting.write(Data(answer.utf8))
        try input.fileHandleForWriting.close()
        let isYes = TerminalPrompt.ask("Continue?", input: input.fileHandleForReading.fileDescriptor,
                                       output: output.fileHandleForWriting.fileDescriptor)
        try output.fileHandleForWriting.close()
        let question = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let unread = String(decoding: input.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        return (isYes, question, unread)
    }
    
    /// Only y or yes, in any case and with spaces around it, is yes: an empty line, no answer, or anything else is no.
    ///
    /// - Throws: The error closing a pipe.
    func testOnlyYesIsYes() throws {
        for answer in ["y\n", "YES\n", "  yes \r\n", "Y"] {
            XCTAssertTrue(try ask(typing: answer).isYes, answer)
        }
        for answer in ["\n", "", "n\n", "no\n", "yess\n", "y es\n", "\nyes\n"] {
            XCTAssertFalse(try ask(typing: answer).isYes, answer)
        }
        XCTAssertEqual(try ask(typing: "y\n").question, "Continue? [y/N] ")
    }
    
    /// One line is read, and no more than its first 256 bytes: the rest stays for whoever reads next.
    ///
    /// - Throws: The error closing a pipe.
    func testOneLineIsRead() throws {
        XCTAssertEqual(try ask(typing: "y\nmore\n").unread, "more\n")
        let long = try ask(typing: String(repeating: "y", count: 300) + "\n")
        XCTAssertFalse(long.isYes)
        XCTAssertEqual(long.unread, String(repeating: "y", count: 44) + "\n")
    }
    
    /// `mute reset` says whose home folder the default set's per-user mutes are for, escaped for a terminal, or that
    /// no one is logged in at the console to have them: over SSH, the console user may be someone else or no one.
    func testResetSaysWhoseHomeItMutes() {
        XCTAssertEqual(MuteCommand.PendingChange.reset(for: .tester).question, """
            Reset the saved mute set to Mac Monitor's default set?
            It mutes the caches and Biome streams of /Users/tester, the home folder of tester, who's logged in at the \
            console.
            """)
        XCTAssertEqual(MuteCommand.PendingChange.reset(for: nil).question, """
            Reset the saved mute set to Mac Monitor's default set?
            No one is logged in at the console, so it leaves out the mutes for a home folder's caches and Biome \
            streams.
            """)
        let odd = ConsoleUser(name: "eve\u{1B}[2J", uid: 503, home: "/Users/eve\u{202E}")
        let question = MuteCommand.PendingChange.reset(for: odd).question
        XCTAssertTrue(question.contains(#"/Users/eve\u{202E}, the home folder of eve\x1B[2J,"#), question)
        XCTAssertEqual(MuteCommand.PendingChange.reset(for: nil).result(MuteList()), .shippedDefault(for: nil))
        XCTAssertEqual(MuteCommand.PendingChange.reset(for: .tester).result(MuteList()), .testDefault)
    }
    
    /// A change counts mutes by path and type: new ones, lost ones, and ones whose events change.
    func testWhatAChangeDoes() {
        let current = MuteList([
            PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL, events: []),
            PathMute(path: "/b", type: ES_MUTE_PATH_TYPE_PREFIX, events: [ES_EVENT_TYPE_NOTIFY_OPEN]),
            PathMute(path: "/c", type: ES_MUTE_PATH_TYPE_TARGET_LITERAL, events: [])
        ])
        let next = MuteList([
            PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL, events: []),
            PathMute(path: "/b", type: ES_MUTE_PATH_TYPE_PREFIX, events: []),
            PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_PREFIX, events: []),
            PathMute(path: "/d", type: ES_MUTE_PATH_TYPE_LITERAL, events: [ES_EVENT_TYPE_NOTIFY_EXEC])
        ])
        let change = MuteListChange(from: current, to: next)
        XCTAssertEqual([change.added, change.removed, change.changed, change.before, change.after], [2, 1, 1, 3, 4])
        XCTAssertFalse(change.isEmpty)
        XCTAssertEqual(change.description, "It adds 2 mutes, removes 1 and changes 1: 3 mutes now, 4 after.")
        XCTAssertTrue(MuteListChange(from: .testDefault, to: .testDefault).isEmpty)
        let one = MuteList([PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL, events: [])])
        XCTAssertEqual(MuteListChange(from: MuteList(), to: one).description,
                       "It adds 1 mute, removes 0 and changes 0: 0 mutes now, 1 after.")
    }
}
