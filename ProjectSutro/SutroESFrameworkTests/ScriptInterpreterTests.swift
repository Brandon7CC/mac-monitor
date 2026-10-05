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
}
