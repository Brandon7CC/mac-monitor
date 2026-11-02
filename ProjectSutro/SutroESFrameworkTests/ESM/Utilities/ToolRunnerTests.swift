//
//  ToolRunnerTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/27/26.
//

import XCTest
@testable import SutroESFramework


final class ToolRunnerTests: XCTestCase {
    /// Runs a shell command.
    ///
    /// - Parameters:
    ///   - command: The command, for `/bin/sh -c`.
    ///   - stream: The stream to capture.
    /// - Returns: The exit status and the captured output as text.
    private func shell(_ command: String, _ stream: ToolRunner.Stream) throws -> (Int32, String) {
        let (status, output) = try ToolRunner.run("/bin/sh", ["-c", command], capturing: stream)
        return (status, String(decoding: output, as: UTF8.self))
    }

    /// Each stream is captured on its own, and the exit status comes back.
    func testCapturesOneStreamAndTheStatus() throws {
        let command = "echo out; echo err >&2; exit 3"
        XCTAssertEqual(try shell(command, .standardOutput).1, "out\n")
        XCTAssertEqual(try shell(command, .standardError).1, "err\n")
        XCTAssertEqual(try shell(command, .standardError).0, 3)
        XCTAssertEqual(try shell("exit 0", .standardOutput).0, 0)
    }

    /// A tool a signal ends is 128 plus the signal, as a shell reports it.
    func testASignalIsItsShellStatus() throws {
        XCTAssertEqual(try shell("kill -TERM $$", .standardOutput).0, 128 + SIGTERM)
    }

    /// A tool that isn't there throws rather than hanging.
    func testAMissingToolThrows() {
        XCTAssertThrowsError(try ToolRunner.run("/nonexistent/tool", [], capturing: .standardOutput))
    }

    /// More output than a pipe holds is read in full.
    func testReadsMoreThanAPipeHolds() throws {
        let (status, output) = try ToolRunner.run("/bin/sh", ["-c", "head -c 300000 /dev/zero"],
                                                  capturing: .standardOutput)
        XCTAssertEqual(status, 0)
        XCTAssertEqual(output.count, 300_000)
    }

    /// The tool inherits standard input, output and error, and no other file descriptor of this process.
    func testInheritsNoOtherDescriptors() throws {
        let leaked = Pipe()
        defer { try? leaked.fileHandleForReading.close(); try? leaked.fileHandleForWriting.close() }
        /// `zsh -c` opens nothing of its own (`sh`, which is bash, opens 10), so any descriptor from 3 up is inherited.
        let probe = "fd=3; while [ $fd -lt 256 ]; do (: <&$fd) 2>/dev/null && echo $fd; fd=$((fd + 1)); done"
        let open = String(decoding: try ToolRunner.run("/bin/zsh", ["-c", probe], capturing: .standardOutput).output,
                          as: UTF8.self)
        XCTAssertEqual(open, "", "Inherited: \(open)")
        XCTAssertGreaterThan(leaked.fileHandleForWriting.fileDescriptor, 2)
    }

    /// Many runs in a row each finish. `Process.waitUntilExit()` hung on a second run in the Security Extension.
    func testManyRunsInARowFinish() throws {
        for run in 0..<200 {
            XCTAssertEqual(try shell("echo \(run)", .standardOutput).1, "\(run)\n")
        }
    }
}
