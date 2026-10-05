//
//  TextOutputTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Text output
/// Pins `macmonitor`'s text lines and what it escapes for a terminal: the exact line for an event, the fallbacks for
/// what's missing, and no control or bidirectional character reaching the terminal in text or JSON.
final class TextOutputTests: XCTestCase {
    private let utc = TextEventFormatter(timeZone: TimeZone(identifier: "UTC")!)
    
    /// A header for an exec.
    ///
    /// - Parameters:
    ///   - path: The executable's path.
    ///   - context: The summary.
    ///   - target: The target path.
    /// - Returns: The header.
    private func exec(path: String? = "/bin/zsh", context: String? = "/bin/ls -la", target: String? = "/bin/ls")
        -> EventHeader {
        EventHeader(sequence: 1, globalSequence: 1, eventType: 9, name: "ES_EVENT_TYPE_NOTIFY_EXEC",
                    time: "2026-10-05T14:03:22.123456789Z",
                    process: EventHeader.Process(pid: 4211, groupID: 4211, user: "root", path: path),
                    context: context, targetPath: target)
    }
    
    /// The line for an exec: time, name, process, user, command line.
    func testTheLine() {
        XCTAssertEqual(utc.line(for: exec()), "14:03:22.123  exec          zsh[4211]  root  /bin/ls -la\n")
    }
    
    /// Times are shown in the formatter's time zone, and a time that isn't eslogger's is shown as it is.
    func testTimesAreLocal() {
        let tokyo = TextEventFormatter(timeZone: TimeZone(identifier: "Asia/Tokyo")!)
        XCTAssertEqual(tokyo.clock("2026-10-05T14:03:22.000000001Z"), "23:03:22.000")
        let honolulu = TextEventFormatter(timeZone: TimeZone(identifier: "Pacific/Honolulu")!)
        XCTAssertEqual(honolulu.clock("2026-10-05T01:00:00.999999999Z"), "15:00:00.999")
        XCTAssertEqual(utc.clock("yesterday\u{1B}[2J"), #"yesterday\x1B[2J"#)
    }
    
    /// Missing fields fall back: no context (or "Not supported") shows the target path, no executable shows "?", and
    /// no user "-".
    func testFallbacks() {
        XCTAssertEqual(utc.line(for: exec(context: nil)), "14:03:22.123  exec          zsh[4211]  root  /bin/ls\n")
        XCTAssertEqual(utc.line(for: exec(context: "Not supported")),
                       "14:03:22.123  exec          zsh[4211]  root  /bin/ls\n")
        XCTAssertEqual(utc.line(for: exec(path: nil, context: "", target: nil)),
                       "14:03:22.123  exec          ?[4211]  root  \n")
        let noUser = EventHeader(sequence: nil, globalSequence: nil, eventType: 79,
                                 name: "ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK", time: "2026-10-05T14:03:22.123456789Z",
                                 process: EventHeader.Process(pid: 1, groupID: 1, user: nil, path: "/sbin/launchd"),
                                 context: nil, targetPath: nil)
        XCTAssertEqual(utc.line(for: noUser), "14:03:22.123  lw_session_unlock  launchd[1]  -  \n")
    }
    
    /// Text escapes ESC, BEL, newlines, tabs, DEL, C1 and the bidirectional controls, in every field.
    func testTextEscapesControls() {
        let hostile = "a\u{1B}[31mb\u{07}c\nd\te\u{7F}f\u{9B}g\u{202E}h\u{2066}i"
        XCTAssertEqual(TerminalSafeText.text(hostile), #"a\x1B[31mb\x07c\nd\te\x7Ff\u{9B}g\u{202E}h\u{2066}i"#)
        let line = utc.line(for: exec(path: "/tmp/\u{1B}]0;pwned\u{07}", context: hostile))
        XCTAssertEqual(line.filter { $0 == "\n" }.count, 1)
        XCTAssertFalse(line.unicodeScalars.dropLast().contains { TerminalSafeText.needsEscape($0) })
    }
    
    /// Plain ASCII and other UTF-8 (accents, CJK, emoji) pass through untouched.
    func testOrdinaryTextIsKept() {
        for text in ["/usr/bin/true", "café", "日本語のファイル", "🏎 fast", ""] {
            XCTAssertEqual(TerminalSafeText.text(text), text)
            let json = Data(#"{"path":"\#(text)"}"#.utf8)
            XCTAssertEqual(TerminalSafeText.json(json), json)
        }
    }
    
    /// JSON escapes only DEL, C1 and the bidirectional controls, stays valid, and reads back as the same value.
    ///
    /// - Throws: The error encoding or parsing the JSON.
    func testJSONEscapesAndStillParses() throws {
        let value = ["path": "x\u{7F}y\u{9B}z\u{202E}é\u{1B}\n✓"]
        var line = try JSONEncoder().encode(value)
        line.append(0x0A)
        let escaped = TerminalSafeText.json(line)
        let text = String(decoding: escaped, as: UTF8.self)
        XCTAssertTrue(text.contains(#"\u007F"#) && text.contains(#"\u009B"#) && text.contains(#"\u202E"#))
        XCTAssertTrue(text.contains("é") && text.contains("✓"))
        XCTAssertTrue(text.hasSuffix("}\n"))
        XCTAssertEqual(text.filter { $0 == "\n" }.count, 1)
        XCTAssertEqual(try JSONDecoder().decode([String: String].self, from: escaped), value)
        XCTAssertFalse(text.unicodeScalars.contains { $0.value >= 0x7F && TerminalSafeText.needsEscape($0) })
    }
}
