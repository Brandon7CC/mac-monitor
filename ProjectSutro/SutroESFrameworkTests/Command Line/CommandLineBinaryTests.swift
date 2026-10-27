//
//  CommandLineBinaryTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/26/26.
//

import XCTest


// MARK: - The built tool
/// Runs the built `macmonitor` and checks its exit statuses and output.
///
/// The tool is looked for next to the test bundle, then in the other configurations' products. The tests skip when
/// no `macmonitor` has been built.
final class CommandLineBinaryTests: XCTestCase {
    /// What a run of the tool left.
    private struct Run {
        let status: Int32
        let output: String
        let error: String
    }

    /// The built `macmonitor`, preferring the test bundle's own configuration.
    ///
    /// A tool older than the framework beside it was built from other sources and can't load it, so it's passed over.
    ///
    /// - Returns: Its URL.
    /// - Throws: `XCTSkip` when no current one has been built.
    private func tool() throws -> URL {
        let products = Bundle(for: Self.self).bundleURL.deletingLastPathComponent()
        let configurations = (try? FileManager.default.contentsOfDirectory(
            at: products.deletingLastPathComponent(), includingPropertiesForKeys: nil)) ?? []
        let candidates = [products] + configurations.filter { $0.standardized != products.standardized }
        let found = candidates.map { $0.appendingPathComponent("macmonitor") }.first { tool in
            FileManager.default.isExecutableFile(atPath: tool.path) && !Self.isStale(tool)
        }
        guard let found else { throw XCTSkip("No current macmonitor is built. Build the macmonitor scheme first.") }
        return found
    }

    /// - Parameter tool: A built `macmonitor`.
    /// - Returns: `true` when the framework beside it was built after it.
    private static func isStale(_ tool: URL) -> Bool {
        let framework = tool.deletingLastPathComponent()
            .appendingPathComponent("SutroESFramework.framework/Versions/A/SutroESFramework")
        let modified = { (url: URL) in
            (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
        }
        guard let toolDate = modified(tool), let frameworkDate = modified(framework) else { return false }
        return toolDate < frameworkDate
    }

    /// Run `macmonitor` to completion.
    ///
    /// The framework is loaded from the tool's own folder, as Xcode does when it runs the tool.
    ///
    /// - Parameters:
    ///   - arguments: Its arguments.
    ///   - outputBytes: Read only this many bytes of standard output, then close it, as `| head -c` does.
    /// - Returns: How it exited and what it wrote.
    /// - Throws: `XCTSkip` when there's no tool, or the error that kept it from running.
    private func run(_ arguments: [String], outputBytes: Int? = nil) throws -> Run {
        let url = try tool()
        let process = Process()
        process.executableURL = url
        process.arguments = arguments
        process.environment = ["DYLD_FRAMEWORK_PATH": url.deletingLastPathComponent().path]
        let (output, error) = (Pipe(), Pipe())
        (process.standardOutput, process.standardError) = (output, error)
        try process.run()
        let written: Data
        if let outputBytes {
            written = output.fileHandleForReading.readData(ofLength: outputBytes)
            try output.fileHandleForReading.close()
        } else {
            written = output.fileHandleForReading.readDataToEndOfFile()
        }
        let said = error.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationReason, .exit, "\(arguments) ended by a signal")
        return Run(status: process.terminationStatus, output: String(decoding: written, as: UTF8.self),
                   error: String(decoding: said, as: UTF8.self))
    }

    /// An unknown command is a usage error: exit 64.
    func testAnUnknownCommandExits64() throws {
        let run = try run(["bogus"])
        XCTAssertEqual(run.status, 64)
        XCTAssertEqual(run.error, "macmonitor: Unknown command 'bogus'. Run 'macmonitor help'.\n")
    }

    /// `stream` without root exits 77 and says to use sudo.
    func testStreamWithoutRootExits77() throws {
        try XCTSkipIf(geteuid() == 0, "The tests run as root.")
        let run = try run(["stream"])
        XCTAssertEqual(run.status, 77)
        XCTAssertTrue(run.error.contains("sudo macmonitor stream"), run.error)
    }

    /// `schema | head -c1` exits 0: a reader that closes early isn't a failure.
    func testAClosedPipeIsASuccess() throws {
        let run = try run(["schema"], outputBytes: 1)
        XCTAssertEqual(run.status, 0)
        XCTAssertEqual(run.output, "{")
    }

    /// `--version` prints the tool's version, such as "macmonitor 3.0.0 (1)".
    func testVersion() throws {
        let run = try run(["--version"])
        XCTAssertEqual(run.status, 0)
        XCTAssertNotNil(run.output.range(of: #"^macmonitor \d+(\.\d+)* \([0-9.]+\)\n$"#, options: .regularExpression),
                        run.output)
    }
}
