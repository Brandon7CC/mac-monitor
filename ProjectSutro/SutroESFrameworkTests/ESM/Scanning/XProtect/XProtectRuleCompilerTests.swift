//
//  XProtectRuleCompilerTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/24/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Compiling in a child process
/// Pins the child's work, run here in-process, and the parent's handling of a child, with small scripts standing in
/// for the Security Extension's executable: the rules it writes, its diagnostics, its status, and a child that hangs
/// or ends before reading its input. The privilege drop needs root, so it's checked on the test VMs.
final class XProtectRuleCompilerTests: XCTestCase {
    /// The library, or the test is skipped.
    private func library() throws -> YaraLibrary {
        guard case .success(let library) = YaraLibrary.shared else { throw XCTSkip("No libyara here.") }
        return library
    }

    /// A new empty file, open for writing.
    private func makeOutput() throws -> (url: URL, descriptor: Int32) {
        let url = try makeTemporaryDirectory(prefix: "XProtectRuleCompilerTests").appendingPathComponent("out.yarc")
        let descriptor = open(url.path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        return (url, descriptor)
    }

    /// An executable script standing in for the child.
    private func makeChild(_ body: String) throws -> String {
        let url = try makeTemporaryDirectory(prefix: "XProtectRuleCompilerTests").appendingPathComponent("child")
        try Data("#!/bin/sh\n\(body)\n".utf8).write(to: url)
        chmod(url.path, 0o755)
        return url.path
    }

    /// Runs the child's work in-process on rule text, with pipes for its input and diagnostics.
    private func runChild(_ text: String,
                          into output: Int32) throws -> (XProtectRuleCompiler.Status, [YaraDiagnostic]) {
        let input = Pipe(), diagnostics = Pipe()
        try input.fileHandleForWriting.write(contentsOf: Data(text.utf8))
        try input.fileHandleForWriting.close()
        let status = XProtectRuleCompiler.runChild(input: input.fileHandleForReading.fileDescriptor, output: output,
                                                   diagnostics: diagnostics.fileHandleForWriting.fileDescriptor)
        try diagnostics.fileHandleForWriting.close()
        let reported = try diagnostics.fileHandleForReading.readToEnd() ?? Data()
        return (status, XProtectRuleCompiler.parse(reported))
    }

    /// Only the compile argument makes a process compile: anything else runs it as itself.
    func testOnlyTheArgumentStartsTheChild() {
        XCTAssertNil(XProtectRuleCompiler.runIfAsked(["/path/to/extension"]))
        XCTAssertNil(XProtectRuleCompiler.runIfAsked(["/path/to/extension", "--other"]))
        XCTAssertNil(XProtectRuleCompiler.runIfAsked([XProtectRuleCompiler.argument]))
    }

    /// A process that isn't root has nothing to drop.
    func testNothingToDropWithoutRoot() throws {
        guard getuid() != 0 else { throw XCTSkip("Runs as root.") }
        XCTAssertTrue(XProtectRuleCompiler.dropPrivileges())
        XCTAssertNotEqual(getuid(), XProtectRuleCompiler.nobody)
    }

    /// The child compiles rule text into rules that load and match, and reports its warnings.
    func testTheChildWritesRulesThatLoad() throws {
        let library = try library()
        let (url, descriptor) = try makeOutput()
        let (status, diagnostics) = try runChild("rule Child { strings: $a = \"x\" condition: $a }", into: descriptor)
        close(descriptor)
        XCTAssertEqual(status, .compiled)
        XCTAssertTrue(diagnostics.contains { !$0.isError && $0.line == 1 }, "\(diagnostics)")

        let reading = open(url.path, O_RDONLY | O_CLOEXEC)
        defer { close(reading) }
        let rules = try YaraRuleSet.load(from: reading, library: library)
        let outcome = Array("x".utf8).withUnsafeBytes { rules.scan($0, timeout: 5) }
        XCTAssertEqual(outcome, .matched([YaraMatch(identifier: "Child", name: nil, matchType: 11)]))
    }

    /// Rule text with an error writes nothing, ends invalid, and says where.
    func testTheChildReportsAnError() throws {
        _ = try library()
        let (url, descriptor) = try makeOutput()
        let (status, diagnostics) = try runChild("rule Broken {\n condition: $missing }", into: descriptor)
        close(descriptor)
        XCTAssertEqual(status, .invalid)
        XCTAssertEqual(diagnostics.first(where: \.isError)?.line, 2)
        XCTAssertEqual(try Data(contentsOf: url), Data())
    }

    /// The parent hands the child its argument and its input, keeps what it writes, and reads its warnings.
    func testTheParentKeepsWhatTheChildWrites() throws {
        let child = try makeChild("""
        [ "$1" = "\(XProtectRuleCompiler.argument)" ] || exit 64
        input=$(cat)
        printf 'compiled:%s' "$input"
        printf '{"isError":false,"line":3,"message":"slow"}\\nnot json\\n' >&2
        """)
        let (url, descriptor) = try makeOutput()
        let diagnostics = try XProtectRuleCompiler.compile(Data("rules".utf8), into: descriptor, executable: child)
        close(descriptor)
        XCTAssertEqual(diagnostics, [YaraDiagnostic(isError: false, line: 3, message: "slow")])
        XCTAssertEqual(try String(contentsOf: url, encoding: .utf8), "compiled:rules")
    }

    /// A child that ends without compiling fails with its status and diagnostics.
    func testAChildThatFailsIsReported() throws {
        let child = try makeChild("""
        cat > /dev/null
        printf '{"isError":true,"line":2,"message":"bad"}\\n' >&2
        exit 65
        """)
        let (_, descriptor) = try makeOutput()
        defer { close(descriptor) }
        XCTAssertThrowsError(try XProtectRuleCompiler.compile(Data("rules".utf8), into: descriptor,
                                                              executable: child)) { error in
            XCTAssertEqual(error as? XProtectRuleCompiler.Failure, .ended(status: 65, diagnostics: [
                YaraDiagnostic(isError: true, line: 2, message: "bad")]))
        }
    }

    /// A child that ends before reading a large input fails cleanly: the parent's write fails, without a signal.
    func testAChildThatEndsEarlyDoesntStopTheParent() throws {
        let child = try makeChild("exit 77")
        let (_, descriptor) = try makeOutput()
        defer { close(descriptor) }
        XCTAssertThrowsError(try XProtectRuleCompiler.compile(Data(count: 4 << 20), into: descriptor,
                                                              executable: child)) { error in
            XCTAssertEqual(error as? XProtectRuleCompiler.Failure, .ended(status: 77, diagnostics: []))
        }
    }

    /// A child past its time is killed, and the compile fails as timed out.
    func testAChildPastItsTimeIsKilled() throws {
        let child = try makeChild("exec /bin/sleep 30")
        let (_, descriptor) = try makeOutput()
        defer { close(descriptor) }
        let start = Date()
        XCTAssertThrowsError(try XProtectRuleCompiler.compile(Data(), into: descriptor, executable: child,
                                                              timeout: 0.3)) { error in
            XCTAssertEqual(error as? XProtectRuleCompiler.Failure, .timedOut)
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 10)
    }

    /// An executable that can't be started fails with the spawn's error.
    func testAMissingExecutableIsReported() throws {
        let (_, descriptor) = try makeOutput()
        defer { close(descriptor) }
        XCTAssertThrowsError(try XProtectRuleCompiler.compile(Data(), into: descriptor,
                                                              executable: "/nonexistent/child")) { error in
            XCTAssertEqual(error as? XProtectRuleCompiler.Failure, .notStarted(ENOENT))
        }
    }
}
