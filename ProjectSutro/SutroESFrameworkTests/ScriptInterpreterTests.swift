//
//  ScriptInterpreterTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Scripting interpreters
/// Pins which executables count as scripting interpreters, whose script Mac Monitor looks for among an exec's arguments
/// when ES leaves the exec's `script` empty (it's only set for a script run directly, such as `./app.ts`).
final class ScriptInterpreterTests: XCTestCase {
    /// Every supported interpreter matches by its name alone, bun included.
    func testInterpreterNames() {
        for name in ["bash", "osascript", "ruby", "perl", "python", "node", "bun", "swift"] {
            XCTAssertTrue(ProcessHelpers.isScriptingInterpreter(name), name)
        }
    }
    
    /// An interpreter's name followed by a version still matches.
    func testVersionedNames() {
        for name in ["python3", "python3.12", "ruby3.3", "perl5.34", "node22"] {
            XCTAssertTrue(ProcessHelpers.isScriptingInterpreter(name), name)
        }
    }
    
    /// Names that only start with an interpreter's name aren't interpreters.
    func testLookalikeNames() {
        for name in ["bundle", "bundler", "bunzip2", "bunx", "python3-config", "swift-frontend", "zsh", ""] {
            XCTAssertFalse(ProcessHelpers.isScriptingInterpreter(name), name)
        }
    }
    
    /// `bun app.ts` and `bun run app.ts` find the script in the working directory; a binary argument isn't a script.
    ///
    /// - Throws: The error writing the temporary files.
    func testBunScriptFromArguments() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try Data("console.log(\"hello\");\n".utf8).write(to: directory.appendingPathComponent("app.ts"))
        try Data([0xCF, 0xFA, 0xED, 0xFE, 0x00, 0x01, 0x02]).write(to: directory.appendingPathComponent("tool"))
        let script = directory.appendingPathComponent("app.ts").path
        /// The script `args` name, resolved in the temporary directory.
        func resolved(_ args: [String]) -> String? {
            ProcessHelpers.parseScriptFromArgs(args: args, workingDirectory: directory.path)
        }
        
        XCTAssertEqual(resolved(["bun", "app.ts"]), script)
        XCTAssertEqual(resolved(["bun", "run", "app.ts"]), script)
        XCTAssertNil(resolved(["bun", "tool"]))
    }
    
    /// Only a regular file can be the script: a FIFO, a directory or a missing file among the arguments isn't one, and
    /// looking never waits. A FIFO with no writer (`bash -c : /tmp/fifo`) used to block the lane building the exec
    /// until something wrote to it.
    ///
    /// - Throws: The error making the temporary directory or the FIFO's folder.
    func testOnlyRegularFilesAreScripts() throws {
        let directory = try makeTemporaryDirectory()
        let fifo = directory.appendingPathComponent("fifo").path
        XCTAssertEqual(mkfifo(fifo, 0o600), 0)
        /// Lets a reader stuck on the FIFO go, should one ever be.
        addTeardownBlock {
            let writer = open(fifo, O_WRONLY | O_NONBLOCK)
            if writer >= 0 { close(writer) }
        }
        try FileManager.default.createDirectory(at: directory.appendingPathComponent("folder"),
                                                withIntermediateDirectories: false)
        
        let looked = DispatchSemaphore(value: 0)
        var script: String?
        var content: String?
        DispatchQueue.global().async {
            script = ProcessHelpers.parseScriptFromArgs(args: ["bash", "-c", ":", fifo, "folder", "missing"],
                                                        workingDirectory: directory.path)
            content = ProcessHelpers.getFileContents(at: fifo)
            looked.signal()
        }
        XCTAssertEqual(looked.wait(timeout: .now() + 5), .success)
        XCTAssertNil(script)
        XCTAssertNil(content)
        XCTAssertNil(ProcessHelpers.getFileContents(at: directory.path))
    }
    
    /// A script's content is its UTF-8 text, cut at the limit back to the end of a whole character.
    ///
    /// - Throws: The error writing the temporary files.
    func testScriptContentStopsAtTheLimit() throws {
        let limit = ProcessHelpers.fileContentsLimit
        let short = try temporaryFile(containing: "echo hi\n", named: "short.sh")
        XCTAssertEqual(ProcessHelpers.getFileContents(at: short.path), "echo hi\n")
        XCTAssertEqual(ProcessHelpers.getFileContents(at: "file://" + short.path), "echo hi\n")
        let empty = try temporaryFile(containing: "", named: "empty.sh")
        XCTAssertEqual(ProcessHelpers.getFileContents(at: empty.path), "")
        
        let exact = String(repeating: "a", count: limit)
        XCTAssertEqual(ProcessHelpers.getFileContents(at: try temporaryFile(containing: exact, named: "exact.sh").path),
                       exact)
        /// "é" is two bytes, the first of them the limit's last.
        let long = String(repeating: "a", count: limit - 1) + "\u{E9}tail"
        XCTAssertEqual(ProcessHelpers.getFileContents(at: try temporaryFile(containing: long, named: "long.sh").path),
                       String(repeating: "a", count: limit - 1))
        
        let binary = try makeTemporaryDirectory().appendingPathComponent("tool")
        try Data([0xCF, 0xFA, 0xED, 0xFE, 0xFF]).write(to: binary)
        XCTAssertNil(ProcessHelpers.getFileContents(at: binary.path))
    }
}
