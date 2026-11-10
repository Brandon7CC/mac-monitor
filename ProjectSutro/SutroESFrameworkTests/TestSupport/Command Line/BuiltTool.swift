//
//  BuiltTool.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest


// MARK: - The built tool
/// The `macmonitor` this build made, run as a child process.
///
/// The test target depends on the `macmonitor` target, so Xcode builds the tool beside the test bundle before the
/// tests run. Without one, the tests that run it are skipped, unless `SUTRO_REQUIRE_TOOL` is `1`, as the
/// SutroESFramework test plan sets it: then they fail.
struct BuiltTool {
    /// How long a run may take, from its launch, before it's killed and the test fails.
    static let deadline: TimeInterval = 10
    /// Does a missing tool fail the test, rather than skip it?
    static let isRequired = ProcessInfo.processInfo.environment["SUTRO_REQUIRE_TOOL"] == "1"

    /// The executable.
    let url: URL

    /// What a run of the tool left.
    struct Run {
        /// Did it exit, or did a signal end it?
        let reason: Process.TerminationReason
        /// Its exit status, or the signal that ended it.
        let status: Int32
        /// What it wrote to standard output.
        let output: String
        /// What it wrote to standard error.
        let error: String
    }

    /// The `macmonitor` beside the test bundle.
    ///
    /// - Returns: The tool.
    /// - Throws: `XCTSkip` when none has been built, or ``BuiltToolError`` then if `SUTRO_REQUIRE_TOOL` is `1`.
    static func current() throws -> BuiltTool {
        let url = Bundle(for: LaunchedTool.self).bundleURL.deletingLastPathComponent()
            .appendingPathComponent("macmonitor")
        guard FileManager.default.isExecutableFile(atPath: url.path) else {
            let reason = "No macmonitor is built beside the tests, at \(url.path)."
            if isRequired { throw BuiltToolError(reason + " SUTRO_REQUIRE_TOOL is 1.") }
            throw XCTSkip(reason + " Build the macmonitor scheme first.")
        }
        return BuiltTool(url: url)
    }

    /// Start the tool, loading the framework from its own folder, as Xcode does when it runs it. Standard error is
    /// read from the start; standard output only from ``LaunchedTool/readOutput(upTo:)`` or
    /// ``LaunchedTool/finish()``, so a test can leave the tool blocked writing it.
    ///
    /// - Parameters:
    ///   - arguments: Its arguments.
    ///   - output: Its standard output: a new pipe unless a test brings one, such as one already full.
    /// - Returns: The running tool.
    /// - Throws: The error that kept it from starting.
    func launch(_ arguments: [String], output: Pipe = Pipe()) throws -> LaunchedTool {
        try LaunchedTool(url: url, arguments: arguments, output: output)
    }

    /// Run the tool to completion, reading standard output and error as it writes them.
    ///
    /// - Parameters:
    ///   - arguments: Its arguments.
    ///   - outputBytes: Read only this many bytes of standard output, then close it, as `| head -c` does.
    /// - Returns: How it ended and what it wrote.
    /// - Throws: ``BuiltToolError`` when it's still running at the ``deadline``, or the error that kept it from
    ///   starting.
    func run(_ arguments: [String], outputBytes: Int? = nil) throws -> Run {
        let launched = try launch(arguments)
        launched.readOutput(upTo: outputBytes)
        return try launched.finish()
    }
}


// MARK: - A running tool
/// One `macmonitor` process: signals to send it, and what it wrote once it's ended.
final class LaunchedTool {
    /// The process.
    let process: Process
    /// When it started, for the deadline.
    private let started = Date()
    /// Its standard output and error.
    private let output: Pipe, error: Pipe
    /// The reads of both, done once each reaches its end.
    private let reads = DispatchGroup()
    /// Signaled once the process has ended.
    private let ended = DispatchSemaphore(value: 0)
    /// What was read. Written on the reading threads and read only after `reads` is done.
    private var written = Data(), said = Data()
    /// Has standard output's read started?
    private var isReadingOutput = false

    /// Start the tool.
    ///
    /// - Parameters:
    ///   - url: The executable.
    ///   - arguments: Its arguments.
    ///   - output: Its standard output.
    /// - Throws: The error that kept it from starting.
    fileprivate init(url: URL, arguments: [String], output: Pipe) throws {
        (process, self.output, error) = (Process(), output, Pipe())
        process.executableURL = url
        process.arguments = arguments
        process.environment = Self.environment(frameworks: url.deletingLastPathComponent())
        (process.standardOutput, process.standardError) = (output, error)
        process.terminationHandler = { [ended] _ in ended.signal() }
        try process.run()
        read(error.fileHandleForReading) { self.said = $0 }
    }

    /// The tool's whole environment: its framework from its own folder, and the tests' coverage file. A tool built
    /// for coverage writes its counts where `LLVM_PROFILE_FILE` says, else to `default.profraw` in the folder it runs
    /// in, so it gets the tests' own setting, or one in the temporary folder when they have none.
    ///
    /// - Parameter frameworks: The folder the framework is in.
    /// - Returns: The environment.
    static func environment(frameworks: URL) -> [String: String] {
        let profile = ProcessInfo.processInfo.environment["LLVM_PROFILE_FILE"]
            ?? FileManager.default.temporaryDirectory.appendingPathComponent("macmonitor-%p.profraw").path
        return ["DYLD_FRAMEWORK_PATH": frameworks.path, "LLVM_PROFILE_FILE": profile]
    }

    /// Start reading standard output, if it hasn't started.
    ///
    /// - Parameter bytes: Read only this many bytes, then close it, as `| head -c` does. `nil` reads to the end.
    func readOutput(upTo bytes: Int? = nil) {
        guard !isReadingOutput else { return }
        isReadingOutput = true
        read(output.fileHandleForReading, upTo: bytes) { self.written = $0 }
    }

    /// Send the process a signal.
    ///
    /// - Parameter number: The signal, such as `SIGINT`.
    func send(_ number: Int32) {
        kill(process.processIdentifier, number)
    }

    /// Wait until the tool's ``SignalTrap`` is set: `SIGINT`, `SIGTERM` and `SIGHUP` ignored, so their signal
    /// sources stop the command. Dispatch registers each source just after its signal is ignored, so this waits a
    /// fifth of a second more for the last of them.
    ///
    /// - Throws: ``BuiltToolError`` when the process ends first, or the deadline passes.
    func waitForSignalTrap() throws {
        let trapped = sigset_t(1 << (SIGINT - 1) | 1 << (SIGTERM - 1) | 1 << (SIGHUP - 1))
        while ignoredSignals() & trapped != trapped {
            guard process.isRunning else { throw BuiltToolError("macmonitor ended before it trapped signals.") }
            guard Date().timeIntervalSince(started) < BuiltTool.deadline else {
                throw BuiltToolError("macmonitor didn't trap signals within \(BuiltTool.deadline) s.")
            }
            usleep(1_000)
        }
        usleep(200_000)
    }

    /// Wait for the process to end, reading whatever standard output is left, and kill it at the deadline.
    ///
    /// - Returns: How it ended and what it wrote.
    /// - Throws: ``BuiltToolError`` when it's still running, or its output still open, at the deadline.
    func finish() throws -> BuiltTool.Run {
        readOutput()
        let deadline = DispatchTime.now() + max(0, BuiltTool.deadline - Date().timeIntervalSince(started))
        let line = process.arguments ?? []
        guard ended.wait(timeout: deadline) == .success else {
            kill(process.processIdentifier, SIGKILL)
            ended.wait()
            throw BuiltToolError("\(line) still ran after \(BuiltTool.deadline) s, so it was killed.")
        }
        guard reads.wait(timeout: .now() + 2) == .success else {
            throw BuiltToolError("\(line) ended, but its output stayed open.")
        }
        return BuiltTool.Run(reason: process.terminationReason, status: process.terminationStatus,
                             output: String(decoding: written, as: UTF8.self),
                             error: String(decoding: said, as: UTF8.self))
    }

    /// Read a file handle on a thread of its own.
    ///
    /// - Parameters:
    ///   - handle: The handle.
    ///   - bytes: Read only this many bytes, then close it. `nil` reads to the end.
    ///   - keep: Called with what was read, before the read counts as done.
    private func read(_ handle: FileHandle, upTo bytes: Int? = nil, keep: @escaping (Data) -> Void) {
        reads.enter()
        DispatchQueue.global().async { [reads] in
            if let bytes {
                keep(handle.readData(ofLength: bytes))
                try? handle.close()
            } else {
                keep(handle.readDataToEndOfFile())
            }
            reads.leave()
        }
    }

    /// - Returns: The signals the process ignores, as the kernel reports them, or none if it's gone.
    private func ignoredSignals() -> sigset_t {
        var info = kinfo_proc(), size = MemoryLayout<kinfo_proc>.stride
        var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, process.processIdentifier]
        guard sysctl(&name, u_int(name.count), &info, &size, nil, 0) == 0, size > 0 else { return 0 }
        return info.kp_proc.p_sigignore
    }
}


// MARK: - Launching from a test
extension XCTestCase {
    /// Start the built `macmonitor` (``BuiltTool/launch(_:output:)``), and kill it when the test ends if it's still
    /// running, so a test that fails part way leaves nothing behind.
    ///
    /// - Parameters:
    ///   - arguments: Its arguments.
    ///   - output: Its standard output.
    /// - Returns: The running tool.
    /// - Throws: As ``BuiltTool/current()`` does, or the error that kept it from starting.
    func launchTool(_ arguments: [String], output: Pipe = Pipe()) throws -> LaunchedTool {
        let launched = try BuiltTool.current().launch(arguments, output: output)
        addTeardownBlock {
            if launched.process.isRunning { launched.send(SIGKILL) }
        }
        return launched
    }
}

// MARK: - Errors
/// A run of the tool that couldn't be finished or started as the test needs.
struct BuiltToolError: Error, CustomStringConvertible, LocalizedError {
    /// What went wrong.
    let description: String

    /// - Parameter description: What went wrong.
    init(_ description: String) {
        self.description = description
    }

    /// What went wrong, as XCTest reports a thrown error.
    var errorDescription: String? { description }
}
