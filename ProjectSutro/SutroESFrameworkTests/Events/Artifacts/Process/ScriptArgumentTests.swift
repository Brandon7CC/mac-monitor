//
//  ScriptArgumentTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Which argument is the script
/// Pins which of an interpreter's arguments Mac Monitor reads as its script
/// (``ScriptInterpreter/scriptArgument(in:)``): the first that isn't an option or an option's value, and none when the
/// code is on the command line.
final class ScriptArgumentTests: XCTestCase {
    /// The argument a command line names as its script.
    ///
    /// - Parameter commandLine: The interpreter's name, then its arguments.
    /// - Returns: The script argument, or `nil` for none.
    private func script(_ commandLine: String...) throws -> String? {
        let interpreter = try XCTUnwrap(ScriptInterpreter.named(commandLine[0]), commandLine[0])
        return interpreter.scriptArgument(in: commandLine.dropFirst())
    }

    /// Code on the command line, a module, or standard input: there's no script file, whatever follows.
    func testInlineCodeHasNoScript() throws {
        let commandLines: [[String]] = [
            ["bash", "-c", "cat \"$1\"", "_", "notes.txt"], ["bash", "-lc", ":", "data.txt"],
            ["bash", "-ec", ":", "x"], ["bash", "-ce", ":", "x"], ["bash", "-s", "x.sh"], ["bash", "-"],
            ["zsh", "-c", ":", "x"], ["dash", "-c", ":", "x"], ["ksh", "-c", ":", "x"], ["csh", "-c", ":", "x"],
            ["tcsh", "-c", ":", "x"], ["tcsh", "-t", "x"],
            ["python3", "-c", "import sys", "data.json"], ["python3", "-cprint(1)", "x"],
            ["python3", "-m", "pip", "install", "-r", "req.txt"], ["python3", "-Im", "json.tool", "x"],
            ["python3", "-", "x.py"],
            ["perl", "-pi", "-e", "s/a/b/", "app.log"], ["perl", "-ne", "print", "x"], ["perl", "-E", "say 1", "x"],
            ["ruby", "-e", "puts 1", "x"], ["ruby", "-S", "rake", "x"],
            ["osascript", "-e", "display dialog \"Password\"", "x"],
            ["node", "-e", "1", "x.js"], ["node", "-p", "1", "x.js"], ["node", "--eval", "1", "x.js"],
            ["node", "--eval=1", "x.js"], ["node", "--print", "1", "x.js"], ["node", "--run", "build"],
            ["bun", "-e", "1", "x.ts"], ["bun", "--eval", "1", "x.ts"],
            ["swift", "-e", "print(1)", "x.swift"],
        ]
        for commandLine in commandLines {
            let interpreter = try XCTUnwrap(ScriptInterpreter.named(commandLine[0]))
            XCTAssertNil(interpreter.scriptArgument(in: commandLine.dropFirst()), commandLine.joined(separator: " "))
        }
    }

    /// Options that aren't code still leave the script to be found, and an option's value is never the script.
    func testOptionsBeforeTheScript() throws {
        let commandLines: [[String]] = [
            ["bash", "-e", "x.sh"], ["bash", "-ex", "x.sh"], ["bash", "-o", "pipefail", "x.sh"],
            ["bash", "-eo", "pipefail", "x.sh"], ["bash", "+o", "posix", "x.sh"], ["bash", "+x", "x.sh"],
            ["bash", "-O", "extglob", "x.sh"], ["bash", "--rcfile", "rc", "x.sh"], ["bash", "--norc", "x.sh"],
            ["bash", "--", "x.sh"], ["bash", "-", "x.sh"], ["bash", "-e", "-", "x.sh"], ["zsh", "-", "x.sh"],
            ["dash", "-", "x.sh"], ["ksh", "-", "x.sh"], ["zsh", "--emulate", "sh", "x.sh"],
            ["zsh", "-o", "errexit", "x.sh"], ["ksh", "-R", "db", "x.sh"],
            ["tcsh", "-e", "x.sh"], ["csh", "-fe", "x.sh"],
            ["python3", "-E", "x.sh"], ["python3", "-W", "ignore", "x.sh"], ["python3", "-Wignore", "x.sh"],
            ["python3", "-X", "utf8", "x.sh"], ["python3", "-Xfrozen_modules=off", "x.sh"],
            ["python3", "-bb", "x.sh"],
            ["perl", "-w", "x.sh"], ["perl", "-I", "lib", "x.sh"], ["perl", "-Ilib", "x.sh"],
            ["perl", "-Mstrict", "x.sh"], ["perl", "-i.bak", "x.sh"], ["perl", "-CSDE", "x.sh"],
            ["perl", "-0777", "x.sh"],
            ["ruby", "-w", "x.sh"], ["ruby", "-r", "json", "x.sh"], ["ruby", "-rjson", "x.sh"],
            ["ruby", "-C", "/tmp", "x.sh"], ["ruby", "-E", "UTF-8", "x.sh"], ["ruby", "-W:no-deprecated", "x.sh"],
            ["ruby", "--disable", "gems", "x.sh"], ["ruby", "--enable", "frozen-string-literal", "x.sh"],
            ["ruby", "--disable=gems", "x.sh"], ["ruby", "--encoding", "UTF-8", "x.sh"],
            ["ruby", "--external-encoding", "UTF-8", "x.sh"], ["ruby", "--internal-encoding", "UTF-8", "x.sh"],
            ["ruby", "--dump", "insns", "x.sh"], ["ruby", "--backtrace-limit", "5", "x.sh"],
            ["osascript", "-l", "JavaScript", "x.sh"], ["osascript", "-s", "eo", "x.sh"], ["osascript", "-se", "x.sh"],
            ["node", "--inspect", "x.sh"], ["node", "--inspect=9229", "x.sh"], ["node", "-r", "pre.js", "x.sh"],
            ["node", "--require", "pre.js", "x.sh"], ["node", "--import=pre.mjs", "x.sh"],
            ["bun", "run", "x.sh"], ["bun", "--preload", "pre.ts", "x.sh"],
            ["swift", "-I", "include", "x.sh"], ["swift", "-module-name", "Tool", "x.sh"],
            ["swift", "-enable-bare-slash-regex", "x.sh"],
            ["tclsh8.5", "-encoding", "utf-8", "x.sh"],
            ["expect", "-f", "x.sh", "data.txt"], ["expect", "-fx.sh"], ["expect", "-d", "-b", "x.sh"],
            ["expect", "-c", "set timeout 5", "x.sh"],
        ]
        for commandLine in commandLines {
            let interpreter = try XCTUnwrap(ScriptInterpreter.named(commandLine[0]))
            XCTAssertEqual(interpreter.scriptArgument(in: commandLine.dropFirst()), "x.sh",
                           commandLine.joined(separator: " "))
        }
    }

    /// Only the first argument that isn't an option can be the script: the ones after it are its arguments.
    func testOnlyTheFirstArgumentIsTheScript() throws {
        XCTAssertEqual(try script("python3", "missing.py", "data.json"), "missing.py")
        XCTAssertEqual(try script("bash", "x.sh", "-c", "y.sh"), "x.sh")
        XCTAssertNil(try script("bash"))
        XCTAssertNil(try script("bash", "-x"))
        XCTAssertNil(try script("bash", "--"))
        /// `bun run run` runs a script named `run`: a subcommand is skipped once.
        XCTAssertEqual(try script("bun", "run", "run"), "run")
    }

    /// `tclsh` runs a file only when it's named first, or after `-encoding name`. With any other option first, `--`
    /// and "-" included, it reads standard input and every argument is data.
    func testTclshRunsOnlyAFileNamedFirst() throws {
        XCTAssertEqual(try script("tclsh", "x.tcl", "-x"), "x.tcl")
        XCTAssertEqual(try script("tclsh", "-encoding", "utf-8", "x.tcl"), "x.tcl")
        for options in [["-x"], ["-norc"], ["--"], ["-"], ["-encoding", "utf-8", "-x"]] {
            let interpreter = try XCTUnwrap(ScriptInterpreter.named("tclsh"))
            XCTAssertNil(interpreter.scriptArgument(in: options + ["data.txt"]), options.joined(separator: " "))
        }
    }

    /// A lone "-" ends a Bourne-style shell's options, as "--" does, while it's standard input to the other
    /// interpreters.
    func testALoneDashEndsAShellsOptions() throws {
        XCTAssertEqual(try script("bash", "-", "evil.sh"), "evil.sh")
        XCTAssertEqual(try script("zsh", "-", "evil.sh", "decoy.txt"), "evil.sh")
        XCTAssertNil(try script("python3", "-", "x.py"))
        XCTAssertNil(try script("ruby", "-", "x.rb"))
        XCTAssertNil(try script("perl", "-", "x.pl"))
    }

    /// `perl -pie` is `-p -i` with the backup extension `e`, so perl takes the code after it as its script's name.
    func testPerlReadsPieAsAnInPlaceExtension() throws {
        XCTAssertEqual(try script("perl", "-pie", "s/a/b/", "app.log"), "s/a/b/")
    }

    /// The command lines that used to record a data file as the script record none, though every file is there.
    func testDataFilesAreNotScripts() throws {
        let directory = try makeTemporaryDirectory()
        for name in ["app.log", "data.json", "req.txt", "notes.txt", "data.txt", "pip", "decoy.txt", "sh", "gems"] {
            try Data("some text\n".utf8).write(to: directory.appendingPathComponent(name))
        }
        let commandLines: [[String]] = [
            ["perl", "-pi", "-e", "s/a/b/", "app.log"], ["perl", "-pie", "s/a/b/", "app.log"],
            ["python3", "-c", "import json", "data.json"], ["python3", "-m", "pip", "install", "-r", "req.txt"],
            ["bash", "-c", "cat \"$1\"", "_", "notes.txt"], ["bash", "-lc", ":", "data.txt"],
            ["python3", "missing.py", "decoy.txt"], ["tclsh", "-norc", "data.txt"],
            ["zsh", "--emulate", "sh", "missing.sh"], ["ruby", "--disable", "gems", "missing.rb"],
        ]
        for commandLine in commandLines {
            let interpreter = try XCTUnwrap(ScriptInterpreter.named(commandLine[0]))
            XCTAssertNil(ProcessHelpers.scriptFromArgs(args: commandLine, interpreter: interpreter,
                                                       workingDirectory: directory.path),
                         commandLine.joined(separator: " "))
        }
    }

    /// A script behind options that aren't code is still found and read.
    func testScriptsBehindOptionsAreFound() throws {
        let directory = try makeTemporaryDirectory()
        for name in ["x.sh", "x.py", "x.pl"] {
            try Data("# script\n".utf8).write(to: directory.appendingPathComponent(name))
        }
        for commandLine in [["bash", "-e", "x.sh"], ["python3", "-E", "x.py"], ["perl", "-w", "x.pl"]] {
            let interpreter = try XCTUnwrap(ScriptInterpreter.named(commandLine[0]))
            let found = ProcessHelpers.scriptFromArgs(args: commandLine, interpreter: interpreter,
                                                      workingDirectory: directory.path)
            XCTAssertEqual(found?.path, directory.appendingPathComponent(commandLine[2]).path)
            XCTAssertEqual(found?.content, "# script\n")
        }
    }
}
