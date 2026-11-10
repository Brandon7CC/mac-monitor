//
//  CommandLineBinaryTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/26/26.
//

import XCTest


// MARK: - The built tool
/// Runs the built `macmonitor` (``BuiltTool``) and checks its exit statuses and output: the process glue that
/// `SutroESFramework` can't test on its own. Its signals are ``CommandLineSignalTests``'.
final class CommandLineBinaryTests: XCTestCase {
    /// Set to `1` when this Mac's Security Extension refuses this user's `macmonitor stream`.
    private static let streamRefusedVariable = "SUTRO_STREAM_REFUSED"

    /// Run the built `macmonitor` to completion. It must exit, not end by a signal.
    ///
    /// - Parameters:
    ///   - arguments: Its arguments.
    ///   - outputBytes: Read only this many bytes of standard output, then close it, as `| head -c` does.
    ///   - tool: The tool: the built one, unless a test brings a copy.
    /// - Returns: How it exited and what it wrote.
    /// - Throws: As ``BuiltTool/current()`` and ``BuiltTool/run(_:outputBytes:)`` do.
    private func run(_ arguments: [String], outputBytes: Int? = nil, tool: BuiltTool? = nil) throws -> BuiltTool.Run {
        let run = try (tool ?? BuiltTool.current()).run(arguments, outputBytes: outputBytes)
        XCTAssertEqual(run.reason, .exit, "\(arguments) ended by signal \(run.status)")
        return run
    }

    /// An unknown command is a usage error: exit 64.
    func testAnUnknownCommandExits64() throws {
        let run = try run(["bogus"])
        XCTAssertEqual(run.status, 64)
        XCTAssertEqual(run.error, "macmonitor: Unknown command 'bogus'. Run 'macmonitor help'.\n")
    }

    /// `stream` without root exits 77 and says to use sudo, whether the Security Extension refuses it with a reason
    /// or, as for an unsigned build, cuts it off before answering.
    ///
    /// What `stream` does depends on the Security Extension this Mac has: with none it exits 69, and one whose
    /// Settings allow this user streams. So the test runs only when `SUTRO_STREAM_REFUSED` is `1`, saying this Mac's
    /// refuses. `--for` ends a stream it accepts after all, so the test fails rather than waits.
    func testStreamWithoutRootExits77() throws {
        try XCTSkipIf(geteuid() == 0, "The tests run as root.")
        try XCTSkipUnless(ProcessInfo.processInfo.environment[Self.streamRefusedVariable] == "1",
                          "Set \(Self.streamRefusedVariable)=1 when this Mac's Security Extension refuses this user.")
        let run = try run(["stream", "--for", "2s"])
        XCTAssertEqual(run.status, 77)
        XCTAssertTrue(run.error.contains("sudo macmonitor stream --for 2s"), run.error)
    }

    /// `schema | head -c1` exits 0: a reader that closes early isn't a failure.
    func testAClosedPipeIsASuccess() throws {
        let run = try run(["schema"], outputBytes: 1)
        XCTAssertEqual(run.status, 0)
        XCTAssertEqual(run.output, "{")
    }

    /// `--version` prints the tool's version, such as "macmonitor 3.0.0 (1)", on its first line. Root gets the
    /// Security Extension's on a second; anyone else gets only the one.
    func testVersion() throws {
        let run = try run(["--version"])
        XCTAssertEqual(run.status, 0)
        let lines = run.output.split(separator: "\n", omittingEmptySubsequences: false)
        XCTAssertNotNil(lines.first?.range(of: #"^macmonitor \d+(\.\d+)* \([0-9.]+\)$"#, options: .regularExpression),
                        run.output)
        XCTAssertEqual(lines.last, "", "The output ends with a newline")
        if getuid() == 0 {
            XCTAssertEqual(lines.count, 3, run.output)
            XCTAssertTrue(lines.dropFirst().first?.hasPrefix("Security Extension ") == true, run.output)
        } else {
            XCTAssertEqual(lines.count, 2, run.output)
        }
    }

    /// Run set-user-ID, so it doesn't run as the user who started it, `macmonitor` refuses each command that talks
    /// to the Security Extension with exit 77 before it connects, saying once to use sudo, and still runs the others.
    /// Only root can make such a copy: it's owned by `nobody`, and root runs it.
    func testASetUserIDCopyExits77() throws {
        try XCTSkipUnless(getuid() == 0, "Only root can make a set-user-ID copy owned by another user.")
        let copy = try setUserIDCopy()
        for line in [["stream"], ["mute", "list"], ["indicators", "list"]] {
            let run = try run(line, tool: copy)
            XCTAssertEqual(run.status, 77, run.error)
            XCTAssertEqual(run.error, """
                macmonitor: '\(line[0])' doesn't run set-user-ID: its real and effective users must match. Run it \
                with sudo instead.

                """, "One line, with one sudo hint")
            XCTAssertEqual(run.output, "")
        }
        let version = try run(["--version"], tool: copy)
        XCTAssertEqual(version.status, 0, version.error)
        XCTAssertTrue(version.output.hasPrefix("macmonitor "), version.output)
    }

    /// A copy of the built tool and its framework, the tool owned by `nobody` and set-user-ID, in a folder anyone may
    /// search. A set-user-ID process ignores `DYLD_FRAMEWORK_PATH` and rpaths that start with `@executable_path`, so
    /// the copy's rpath is changed to its folder, and the copy signed again. The folder's path is short enough to fit
    /// where `@executable_path/../Frameworks` was.
    ///
    /// - Returns: The copy.
    /// - Throws: The error copying, changing or signing it.
    private func setUserIDCopy() throws -> BuiltTool {
        let built = try BuiltTool.current().url, files = FileManager.default
        let name = "mm-" + UUID().uuidString.prefix(8).lowercased()
        let folder = URL(fileURLWithPath: "/private/tmp", isDirectory: true).appendingPathComponent(name)
        try files.createDirectory(at: folder, withIntermediateDirectories: false,
                                  attributes: [.posixPermissions: 0o755])
        addTeardownBlock { try? files.removeItem(at: folder) }
        let tool = folder.appendingPathComponent("macmonitor")
        try files.copyItem(at: built, to: tool)
        try files.copyItem(at: built.deletingLastPathComponent().appendingPathComponent("SutroESFramework.framework"),
                           to: folder.appendingPathComponent("SutroESFramework.framework"))
        try execute("/usr/bin/xcrun", "install_name_tool", "-rpath", "@executable_path/../Frameworks", folder.path,
                    tool.path)
        try execute("/usr/bin/codesign", "--force", "--sign", "-", tool.path)
        /// The owner first: changing it clears the set-user-ID bit.
        try files.setAttributes([.ownerAccountID: NSNumber(value: UInt32.max - 1)], ofItemAtPath: tool.path)
        try files.setAttributes([.posixPermissions: 0o4755], ofItemAtPath: tool.path)
        return BuiltTool(url: tool)
    }

    /// Run a developer tool to completion. It must exit 0.
    ///
    /// - Parameters:
    ///   - path: The executable.
    ///   - arguments: Its arguments.
    /// - Throws: ``BuiltToolError`` when it fails, or the error that kept it from starting.
    private func execute(_ path: String, _ arguments: String...) throws {
        let process = try Process.run(URL(fileURLWithPath: path), arguments: arguments)
        process.waitUntilExit()
        guard process.terminationReason == .exit, process.terminationStatus == 0 else {
            throw BuiltToolError("\(path) \(arguments) failed with \(process.terminationStatus).")
        }
    }
}
