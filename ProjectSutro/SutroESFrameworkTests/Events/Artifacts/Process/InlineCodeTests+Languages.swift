//
//  InlineCodeTests+Languages.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Python, Perl, Ruby and Node
extension InlineCodeTests {
    /// `python -c` takes its value, attached or the next argument, and ends python's options: what follows is
    /// `sys.argv`, a second `-c` too (`python3 -c 'print(__import__("sys").argv)' -x y` prints `['-c', '-x', 'y']`).
    func testPythonDashC() throws {
        let command = "import base64; exec(base64.b64decode('cHJpbnQoMSk='))"
        let found = try XCTUnwrap(code("python3", "-c", command))
        XCTAssertEqual(found.text, command)
        XCTAssertEqual(found.language, .python)
        XCTAssertEqual(found.source, "From python3's -c argument.")
        assertCode([["python3", "-c", command, "data.json"], ["python3", "-c" + command], ["python3", "-Ic", command],
                    ["python3", "-I", "-c", command], ["python3", "-W", "ignore", "-c", command],
                    ["python3", "-Wignore", "-c", command], ["python3", "-X", "utf8", "-c", command],
                    ["python3", "-c", command, "-c", "print(2)"], ["python3.12", "-c", command],
                    ["python", "-c", command], ["python3", "--check-hash-based-pycs", "never", "-c", command]],
                   command, options: ["-c"])
    }

    /// A script, a module or standard input is no inline code, and nor is a `-c` after one: it's an argument.
    func testPythonScriptsAreNotInlineCode() {
        assertNoCode([["python3", "x.py"], ["python3", "-m", "pip", "install", "-r", "req.txt"],
                      ["python3", "-m", "json.tool", "-c", "print(1)"], ["python3", "-", "x"],
                      ["python3", "x.py", "-c", "print(1)"], ["python3", "-c"], ["python3", "-E", "x.py"]])
    }

    /// Perl joins every `-e` and `-E` a line each, as `-e 'print ord(substr("a' -e 'b", 1, 1))'` shows by printing
    /// 10, and reads options after them until its first other argument.
    func testPerlDashE() throws {
        let found = try XCTUnwrap(code("perl", "-E", "say 1;", "-e", "say 2"))
        XCTAssertEqual(found.text, "say 1;\nsay 2")
        XCTAssertEqual(found.options, ["-E", "-e"])
        XCTAssertEqual(found.language, .perl)
        XCTAssertEqual(found.source, "From perl's 2 -E and -e arguments, joined a line each, as perl does.")
        let fetch = #"use LWP::Simple; print get("https://example.com/");"#
        assertCode([["perl", "-e", fetch], ["perl", "-e" + fetch], ["perl", "-MLWP", "-e", fetch],
                    ["perl", "-I", "lib", "-e", fetch], ["perl", "-le", fetch], ["perl", "-ne", fetch, "app.log"],
                    ["perl", "-e", fetch, "-w"], ["perl5.34", "-e", fetch]],
                   fetch, options: ["-e"])
        assertCode([["perl", "-pi", "-e", "s/a/b/", "app.log"], ["perl", "-i.bak", "-pe", "s/a/b/", "app.log"]],
                   "s/a/b/", options: ["-e"])
        assertCode([["perl", "-e", "print 1;", "-e", "print 2;", "data.txt", "-e", "x"]], "print 1;\nprint 2;",
                   options: ["-e", "-e"])
    }

    /// `perl -pie` is `-p -i` with the backup extension `e`, so perl runs the next argument as a script file.
    func testPerlScriptsAreNotInlineCode() {
        assertNoCode([["perl", "x.pl"], ["perl", "-w", "x.pl"], ["perl", "-pie", "s/a/b/", "app.log"],
                      ["perl", "-e"], ["perl", "x.pl", "-e", "print 1"]])
    }

    /// Ruby joins every `-e` a line each (`ruby -e 'p "a' -e 'b".bytes'` prints `[97, 10, 98]`), and reads options
    /// after them until its first other argument.
    func testRubyDashE() throws {
        let fetch = #"puts Net::HTTP.get(URI("https://example.com/"))"#
        let found = try XCTUnwrap(code("ruby", "-rnet/http", "-e", fetch))
        XCTAssertEqual(found.text, fetch)
        XCTAssertEqual(found.language, .ruby)
        XCTAssertEqual(found.source, "From ruby's -e argument.")
        assertCode([["ruby", "-e", fetch], ["ruby", "-e" + fetch], ["ruby", "-r", "net/http", "-e", fetch],
                    ["ruby", "--disable", "gems", "-e", fetch], ["ruby", "--disable=gems", "-e", fetch],
                    ["ruby", "-e", fetch, "--", "x"], ["ruby", "-ne", fetch, "app.log"], ["ruby", "-e", fetch, "-w"]],
                   fetch, options: ["-e"])
        assertCode([["ruby", "-e", "a = 1", "-e", "p a"]], "a = 1\np a", options: ["-e", "-e"])
    }

    /// A Ruby script, or one found on `PATH`, is no inline code.
    func testRubyScriptsAreNotInlineCode() {
        assertNoCode([["ruby", "x.rb"], ["ruby", "-S", "rake", "-e", "x"], ["ruby", "-e"], ["ruby", "x.rb", "-e", "x"]])
    }

    /// Node's code is the value of `-e`, `-p`, `-pe`, `--eval` or `--print`, the next argument or after "=". Its
    /// options parser keeps the last one given.
    func testNodeEval() throws {
        let command = "require('child_process').exec('id')"
        let found = try XCTUnwrap(code("node", "--eval=" + command))
        XCTAssertEqual(found.text, command)
        XCTAssertEqual(found.language, .javascript)
        XCTAssertEqual(found.source, "From node's --eval argument.")
        for option in ["-e", "-p", "-pe", "--eval", "--print"] {
            assertCode([["node", option, command], ["node", option, command, "x.js"],
                        ["node", "-r", "pre.js", option, command], ["node", "--require", "pre.js", option, command],
                        ["node", "--inspect", option, command], ["node22", option, command],
                        ["node", option, "1", option, command]],
                       command, options: [option])
        }
        assertCode([["node", "--print=" + command]], command, options: ["--print"])
    }

    /// A Node script, a package script, and an option cluster Node doesn't know are no inline code.
    func testNodeScriptsAreNotInlineCode() {
        assertNoCode([["node", "x.js"], ["node", "--run", "build"], ["node", "x.js", "-e", "1"], ["node", "-e"],
                      ["node", "-ep", "1"], ["node", "--inspect", "x.js"]])
    }
}
