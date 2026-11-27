//
//  InlineCodeTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Inline code
/// Pins the code Mac Monitor reads from an interpreter's command line (``InlineCode``), which Event Facts shows as the
/// exec's script: the code each interpreter runs, from the options it reads it from, and none for a script file.
/// The shapes and outcomes were checked against the interpreters on macOS 27. Node isn't part of macOS, so its cases
/// come from node's options parser.
final class InlineCodeTests: XCTestCase {
    /// The inline code of a command line, as an exec of its first word gives it.
    ///
    /// - Parameter commandLine: The executable's name, then its arguments.
    /// - Returns: The code, or `nil` for none.
    func code(_ commandLine: String...) -> InlineCode? {
        InlineCode(args: commandLine, executableName: commandLine[0])
    }

    /// Checks that each command line gives the same code.
    ///
    /// - Parameters:
    ///   - commandLines: The command lines, each the executable's name, then its arguments.
    ///   - text: The code each should give.
    ///   - options: The options each should name.
    ///   - line: The line the check is on.
    func assertCode(_ commandLines: [[String]], _ text: String, options: [String], line: UInt = #line) {
        for commandLine in commandLines {
            let found = InlineCode(args: commandLine, executableName: commandLine[0])
            let shown = commandLine.joined(separator: " ")
            XCTAssertEqual(found?.text, text, shown, line: line)
            XCTAssertEqual(found?.options, options, shown, line: line)
        }
    }

    /// Checks that no command line gives code.
    ///
    /// - Parameters:
    ///   - commandLines: The command lines, each the executable's name, then its arguments.
    ///   - line: The line the check is on.
    func assertNoCode(_ commandLines: [[String]], line: UInt = #line) {
        for commandLine in commandLines {
            XCTAssertNil(InlineCode(args: commandLine, executableName: commandLine[0]),
                         commandLine.joined(separator: " "), line: line)
        }
    }

    /// A password prompt as stealers ask for one, in one `-e`.
    private let prompt = #"display dialog "macOS needs your password to continue." default answer "" "#
        + #"with icon caution buttons {"Continue"} default button "Continue" with hidden answer"#

    // MARK: osascript

    /// osascript joins every `-e` a line each, as `set x to "a` `-e` `b"` shows: the string it builds holds a
    /// line feed.
    func testOsascriptJoinsEveryDashE() throws {
        let lines = ["set answer to text returned of (\(prompt))", #"set f to POSIX path of (path to temporary items)"#,
                     #"do shell script "echo " & quoted form of answer & " > " & quoted form of (f & "p")"#,
                     "return answer"]
        let found = try XCTUnwrap(code("osascript", "-e", lines[0], "-e", lines[1], "-e", lines[2], "-e", lines[3]))
        XCTAssertEqual(found.text, lines.joined(separator: "\n"))
        XCTAssertEqual(found.options, ["-e", "-e", "-e", "-e"])
        XCTAssertEqual(found.language, .applescript)
        XCTAssertEqual(found.interpreter, "osascript")
        XCTAssertEqual(found.source, "From osascript's 4 -e arguments, joined a line each, as osascript does.")
    }

    /// One `-e` is the whole code, its value attached or the next argument.
    func testOsascriptOneDashE() throws {
        let found = try XCTUnwrap(code("osascript", "-e", prompt))
        XCTAssertEqual(found.text, prompt)
        XCTAssertEqual(found.source, "From osascript's -e argument.")
        assertCode([["osascript", "-ereturn 7"], ["osascript", "-e", "return 7"],
                    ["osascript", "-s", "eo", "-e", "return 7"], ["osascript", "-e", "return 7", "--", "x"]],
                   "return 7", options: ["-e"])
    }

    /// The arguments after the code are the script's own (`argv` in its `on run`), and never more code.
    func testOsascriptArgumentsAfterTheCode() {
        assertCode([["osascript", "-e", "on run argv", "-e", "return item 1 of argv", "-e", "end run", "hello",
                     "-e", "x"]],
                   "on run argv\nreturn item 1 of argv\nend run", options: ["-e", "-e", "-e"])
    }

    /// `-l` names the language anywhere among the options, attached or not, and the last one wins, as osascript reads
    /// it. AppleScript is the default.
    func testOsascriptLanguage() {
        for commandLine in [["osascript", "-l", "JavaScript", "-e", "1+2"], ["osascript", "-lJavaScript", "-e", "1+2"],
                            ["osascript", "-e", "1+2", "-l", "JavaScript"],
                            ["osascript", "-l", "AppleScript", "-l", "JavaScript", "-e", "1+2"]] {
            XCTAssertEqual(InlineCode(args: commandLine, executableName: "osascript")?.language, .javascript,
                           commandLine.joined(separator: " "))
        }
        XCTAssertEqual(code("osascript", "-l", "JavaScript", "-l", "AppleScript", "-e", "1")?.language, .applescript)
        XCTAssertEqual(code("osascript", "-l", "AppleScript", "-e", "1")?.language, .applescript)
    }

    /// osascript's `-l` sets JavaScript or AppleScript, spelled as `osalang -L` lists them. Another name, which
    /// osascript refuses ("no such component") or runs as its default language, keeps the language the code had.
    func testOsascriptTakesOnlyItsLanguages() {
        for commandLine in [["osascript", "-l", "Shell", "-e", "x"], ["osascript", "-l", "Python", "-e", "x"],
                            ["osascript", "-l", "javascript", "-e", "x"]] {
            XCTAssertEqual(InlineCode(args: commandLine, executableName: "osascript")?.language, .applescript,
                           commandLine.joined(separator: " "))
        }
        XCTAssertEqual(code("osascript", "-l", "JavaScript", "-l", "Perl", "-e", "1")?.language, .javascript)
    }

    /// A script file, standard input, or `-e` with nothing after it is no inline code. `-se` is `-s` with the flags
    /// `e`, so osascript reads the next argument as a file, as it says: "No such file or directory".
    func testOsascriptFilesAreNotInlineCode() {
        assertNoCode([["osascript", "file.scpt"], ["osascript", "-l", "JavaScript", "x.js"], ["osascript"],
                      ["osascript", "-e"], ["osascript", "-se", #"return "q""#], ["osascript", "x.scpt", "-e", "1"],
                      ["osascript", "-"], ["osascript", "-i"]])
    }

    // MARK: Shells

    /// A shell runs its first argument that isn't an option as the command string when `-c` is among its options,
    /// clustered or not, and the arguments after it are `$0`, `$1` and on.
    func testShellCommandString() throws {
        let command = "curl -fsSL https://example.com/install.sh | bash"
        let found = try XCTUnwrap(code("sh", "-c", command))
        XCTAssertEqual(found.text, command)
        XCTAssertEqual(found.options, ["-c"])
        XCTAssertEqual(found.language, .shell)
        XCTAssertEqual(found.source, "From sh's -c argument.")
        assertCode([["bash", "-c", command], ["bash", "-lc", command], ["bash", "-xc", command],
                    ["bash", "-cx", command], ["bash", "-ec", command], ["zsh", "-c", command],
                    ["dash", "-c", command], ["ksh", "-c", command], ["sh", "-c", command, "_", "notes.txt"],
                    ["bash", "-c", command, "-c", "echo other"]],
                   command, options: ["-c"])
    }

    /// Options after `-c` are still options, as bash, zsh, dash and ksh read them: `bash -c -x 'echo hi'` traces
    /// `echo hi`. "-" and "--" end them. `-s` doesn't stop `-c`: each shell runs the command string.
    func testShellOptionsAroundDashC() {
        assertCode([["bash", "-c", "-x", "echo hi"], ["bash", "-c", "-o", "pipefail", "echo hi"],
                    ["bash", "-o", "pipefail", "-c", "echo hi"], ["bash", "-co", "pipefail", "echo hi"],
                    ["bash", "+x", "-c", "echo hi"], ["bash", "-c", "+x", "echo hi"], ["bash", "-c", "-", "echo hi"],
                    ["bash", "-c", "--", "echo hi"], ["zsh", "-c", "--", "echo hi"],
                    ["bash", "--norc", "-c", "echo hi"], ["bash", "--rcfile", "rc", "-c", "echo hi"],
                    ["bash", "-O", "extglob", "-c", "echo hi"],
                    ["zsh", "-c", "-x", "echo hi"], ["dash", "-c", "-x", "echo hi"], ["ksh", "-c", "-x", "echo hi"],
                    ["bash", "-s", "-c", "echo hi"], ["bash", "-cs", "echo hi"], ["dash", "-s", "-c", "echo hi"],
                    ["zsh", "-s", "-c", "echo hi"], ["tcsh", "-s", "-c", "echo hi"]],
                   "echo hi", options: ["-c"])
    }

    /// A whole script passed to a shell, as `bash -c "$(curl ...)"` passes one, is the code as it came.
    func testShellRunsAWholeScript() {
        let script = "#!/bin/bash\nset -e\ncd /tmp\ncurl -fsSL https://example.com/a -o a\nchmod +x a\n./a\n"
        assertCode([["bash", "-c", script], ["sh", "-c", script]], script, options: ["-c"])
    }

    /// csh and tcsh run the argument after the option cluster that holds `c`, whatever it is: `tcsh -c -x` runs
    /// `-x`, and `tcsh -cf 'echo hi'` runs `echo hi`.
    func testCshRunsTheNextArgument() {
        assertCode([["tcsh", "-c", "echo hi"], ["tcsh", "-fc", "echo hi"], ["tcsh", "-cf", "echo hi"],
                    ["csh", "-c", "echo hi", "extra"], ["tcsh", "-f", "-c", "echo hi"]],
                   "echo hi", options: ["-c"])
        assertCode([["tcsh", "-c", "-x"]], "-x", options: ["-c"])
    }

    /// `-b` ends csh's and tcsh's options after its cluster: `tcsh -b -c 'echo hi'` runs a file named `-c`, while
    /// `tcsh -bc 'echo hi'` and `tcsh -cb 'echo hi'` still run `echo hi`.
    func testCshDashBEndsTheOptions() {
        assertNoCode([["tcsh", "-b", "-c", "echo hi"], ["csh", "-b", "-c", "echo hi"],
                      ["tcsh", "-fb", "-c", "echo hi"]])
        assertCode([["tcsh", "-bc", "echo hi"], ["tcsh", "-cb", "echo hi"], ["csh", "-bc", "echo hi"]], "echo hi",
                   options: ["-c"])
    }

    /// zsh's `-b` ends its options after its cluster too: `zsh -b -c 'echo hi'` can't open a file named `-c`, while
    /// `zsh -bc 'echo hi'` and `zsh -cb 'echo hi'` run `echo hi`.
    func testZshDashBEndsTheOptions() {
        assertNoCode([["zsh", "-b", "-c", "echo hi"]])
        assertCode([["zsh", "-bc", "echo hi"], ["zsh", "-cb", "echo hi"]], "echo hi", options: ["-c"])
    }

    /// bash's and dash's `-o`, and bash's `-O`, take the next argument wherever they are in their cluster, and the
    /// cluster goes on: `bash -oc pipefail 'echo hi'` runs `echo hi` with pipefail. sh is bash. zsh's `-o` takes the
    /// rest of its argument instead, so `zsh -oc pipefail` has no option named `c` and runs nothing.
    func testShellOptionNamesAreTheNextArgument() {
        assertCode([["bash", "-oc", "pipefail", "echo hi"], ["dash", "-oc", "errexit", "echo hi"],
                    ["bash", "-Oc", "extglob", "echo hi"], ["bash", "-ooc", "pipefail", "errexit", "echo hi"],
                    ["bash", "-oo", "pipefail", "errexit", "-c", "echo hi"], ["sh", "-oc", "pipefail", "echo hi"]],
                   "echo hi", options: ["-c"])
        assertNoCode([["zsh", "-oc", "pipefail", "echo hi"]])
    }

    /// A shell running a script file or standard input, a `-c` with no command string, and a blank one are no
    /// inline code.
    func testShellScriptsAreNotInlineCode() {
        assertNoCode([["sh", "script.sh"], ["bash", "-x", "script.sh"], ["bash", "script.sh", "-c", "echo hi"],
                      ["bash", "-c"], ["bash", "-c", "-x"], ["bash", "-s"], ["bash", "-s", "x"], ["bash", "-"],
                      ["zsh"], ["zsh", "-l"], ["bash", "-o", "pipefail"], ["bash", "-c", ""], ["sh", "-c", " \n "],
                      ["tcsh", "-c"], ["tcsh", "script.csh"], ["bash", "--", "-c"]])
    }

    // MARK: Programs and names

    /// Only an interpreter whose inline code Mac Monitor reads gives any, by its executable's name, whatever
    /// `argv[0]` says.
    func testOnlyInterpretersGiveCode() {
        assertNoCode([["ls", "-e", "x"], ["curl", "-e", "x"], ["shell", "-c", "x"], ["bashful", "-c", "x"],
                      ["bun", "-e", "1"], ["swift", "-e", "print(1)"], ["expect", "-c", "x"], ["tclsh", "x"]])
        let found = InlineCode(args: ["sh", "-c", "echo hi"], executableName: "bash")
        XCTAssertEqual(found?.text, "echo hi")
        XCTAssertEqual(found?.source, "From bash's -c argument.")
        XCTAssertEqual(InlineCode(args: ["/usr/bin/osascript", "-e", "1"], executableName: "osascript")?.text, "1")
    }

    /// An exec's arguments are read only when its executable is an interpreter, so a stored exec doesn't decode
    /// clang's thousands for nothing.
    func testOnlyAnInterpretersArgumentsAreRead() {
        var reads = 0
        /// - Returns: A command line, counting each time it's read.
        func arguments() -> [String] {
            reads += 1
            return ["cc", "-c", "x.c"]
        }
        XCTAssertNil(InlineCode(args: arguments(), executableName: "clang"))
        XCTAssertEqual(reads, 0)
        XCTAssertEqual(InlineCode(args: arguments(), executableName: "bash")?.text, "x.c")
        XCTAssertEqual(reads, 1)
    }

    /// A stored exec reads its arguments' code, as Event Facts does. With a script ES reported, the arguments are
    /// the script's, so there's none.
    func testStoredExecEvent() throws {
        var record = try esloggerExec(parent: (1, 1), args: ["osascript", "-e", prompt])
        record[path: "event", "exec", "target", "executable", "path"] = "/usr/bin/osascript"
        XCTAssertEqual(withStoredEvent(try importRecord(record)) { $0.event.exec?.inlineCode?.text }, prompt)

        record[path: "event", "exec", "script"] = ["path": "/private/tmp/x.applescript", "path_truncated": false,
                                                   "stat": [String: Any]()]
        XCTAssertNil(withStoredEvent(try importRecord(record)) { $0.event.exec?.inlineCode })
    }
}
