//
//  CommandLineSignalTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest


// MARK: - Signals
/// Sends the built `macmonitor` (``BuiltTool``) signals while `validate` checks a long trace, and checks how it ends:
/// its `SignalTrap` stops the check on the first `SIGINT`, `SIGTERM` or `SIGHUP`, writes the report so far and exits
/// by that signal, so a shell sees 130 for Ctrl-C; a second signal exits at once with 128 plus its number.
final class CommandLineSignalTests: XCTestCase {
    /// The records in the long trace: enough that checking them takes seconds.
    private static let longTraceRecords = 200_000
    /// The bytes left free in a full standard output: the report's first line fits, and the rest of it, thousands of
    /// bytes, waits. It's more than `PIPE_BUF` (512 bytes), which a pipe takes whole or not at all.
    private static let room = 384
    /// How long the first signal may take to fill standard output: well under a whole check, which takes seconds.
    private static let stopTime: TimeInterval = 2

    /// A trace `validate` takes seconds to check: empty records, each invalid.
    ///
    /// - Returns: Its path.
    /// - Throws: The error writing it.
    private func longTrace() throws -> String {
        try temporaryFile(containing: String(repeating: "{}\n", count: Self.longTraceRecords), named: "long.jsonl").path
    }

    /// Start `validate` on a long trace, and wait until it traps signals.
    ///
    /// - Parameters:
    ///   - path: The trace.
    ///   - output: Its standard output.
    /// - Returns: The running tool.
    /// - Throws: As ``BuiltTool/current()`` does, or ``BuiltToolError`` when it doesn't trap signals.
    private func validate(_ path: String, output: Pipe = Pipe()) throws -> LaunchedTool {
        let tool = try launchTool(["validate", path], output: output)
        try tool.waitForSignalTrap()
        return tool
    }

    /// A first signal stops the check: the report so far is written, saying so, and the tool ends by the signal.
    ///
    /// - Parameters:
    ///   - number: The signal.
    ///   - file: The test's file.
    ///   - line: The test's line.
    /// - Throws: As ``validate(_:output:)`` and ``LaunchedTool/finish()`` do.
    private func assertEndsBy(_ number: Int32, file: StaticString = #filePath, line: UInt = #line) throws {
        let path = try longTrace()
        let tool = try validate(path)
        tool.send(number)
        let run = try tool.finish()
        XCTAssertEqual(run.reason, .uncaughtSignal, "Exited \(run.status)", file: file, line: line)
        XCTAssertEqual(run.status, number, file: file, line: line)
        XCTAssertTrue(run.output.hasPrefix("\(path): "), run.output, file: file, line: line)
        XCTAssertTrue(run.output.contains("Stopped before the end of the file."), run.output, file: file, line: line)
        XCTAssertEqual(run.error, "", file: file, line: line)
    }

    /// Ctrl-C stops `validate`, which ends by `SIGINT`: 130 in a shell.
    func testValidateEndsBySIGINT() throws {
        try assertEndsBy(SIGINT)
    }

    /// `kill` stops `validate`, which ends by `SIGTERM`: 143 in a shell.
    func testValidateEndsBySIGTERM() throws {
        try assertEndsBy(SIGTERM)
    }

    /// A closed terminal stops `validate`, which ends by `SIGHUP`: 129 in a shell.
    func testValidateEndsBySIGHUP() throws {
        try assertEndsBy(SIGHUP)
    }

    /// A second signal exits at once with 128 plus its number, without waiting for the stop to finish.
    ///
    /// Standard output is a pipe left all but full, so the report so far fills it and waits. Its first line, written
    /// within ``stopTime``, says it stopped before the end: that shows the first Ctrl-C stopped the check. The second
    /// finds the tool still waiting to write: it exits 130, not by the signal, before the pipe is read, and the rest
    /// of the report is never written.
    func testASecondSignalExitsAtOnce() throws {
        let path = try longTrace(), output = Pipe()
        let capacity = try output.fill(leaving: Self.room)
        let tool = try validate(path, output: output)
        tool.send(SIGINT)
        XCTAssertTrue(waitUntil(timeout: Self.stopTime) { output.buffered == capacity },
                      "The first signal wrote no report within \(Self.stopTime) s")
        tool.send(SIGINT)
        XCTAssertTrue(waitUntil { !tool.process.isRunning }, "The second signal didn't end it")
        let run = try tool.finish()
        XCTAssertEqual(run.reason, .exit, "Ended by signal \(run.status)")
        XCTAssertEqual(run.status, 128 + SIGINT)
        XCTAssertEqual(run.output.utf8.count, capacity)
        /// What the tool wrote: the pipe's last bytes. The temporary folder's path is ASCII, so its characters are its
        /// bytes.
        let written = String(run.output.suffix(Self.room))
        XCTAssertTrue(written.hasPrefix("\(path): "), written)
        XCTAssertTrue(written.contains("Stopped before the end of the file.\n"), written)
    }
}


// MARK: - A full pipe
private extension Pipe {
    /// The bytes waiting to be read, as `fstat` reports a pipe's.
    var buffered: Int {
        var status = stat()
        guard fstat(fileHandleForReading.fileDescriptor, &status) == 0 else { return -1 }
        return Int(status.st_size)
    }

    /// Fill the pipe until a write would block, then read back a little, so a writer can add only that much before
    /// it blocks.
    ///
    /// - Parameter room: The bytes to read back.
    /// - Returns: How many bytes the pipe holds when full.
    /// - Throws: `POSIXError` when a write fails other than by being full.
    func fill(leaving room: Int) throws -> Int {
        let descriptor = fileHandleForWriting.fileDescriptor, flags = fcntl(descriptor, F_GETFL)
        /// The writer the test starts shares the flags, so they're put back before it does.
        fcntl(descriptor, F_SETFL, flags | O_NONBLOCK)
        defer { fcntl(descriptor, F_SETFL, flags) }
        var capacity = 0
        /// Large writes first, so the pipe grows to its largest buffer while it's empty.
        for size in [65_536, 4_096, 512, 1] {
            let chunk = [UInt8](repeating: UInt8(ascii: "x"), count: size)
            while true {
                let written = write(descriptor, chunk, size)
                guard written > 0 else { break }
                capacity += written
            }
            guard errno == EAGAIN else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        }
        _ = fileHandleForReading.readData(ofLength: room)
        return capacity
    }
}
