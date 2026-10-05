//
//  LaunchedByParentExportTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Storing and exporting the launched-by parent
/// Pins how the event store keeps an exec's or fork's launched-by parent, and how exports write it: as Mac Monitor's
/// addition at `event.exec.launched_by_parent` and `event.fork.launched_by_parent`, with every eslogger key path and
/// value unchanged.
final class LaunchedByParentExportTests: XCTestCase {
    /// The shell, as eslogger names it in ``XCTestCase/esloggerExec(parent:originalPPID:env:)``.
    private let shell = AuditToken(pid: 401, pidversion: 4010, asid: 100_001, auid: 4_294_967_295, euid: 0, ruid: 0,
                                   rgid: 0, egid: 0)
    
    /// The shell's answer for the exec.
    private var shellAnswer: LaunchedByParent {
        LaunchedByParent(source: .unixParent, audit_token: shell, path: "/bin/zsh", resolved_by: .securityExtension)
    }
    
    /// eslogger's exec of `/usr/libexec/exampled` by the shell.
    ///
    /// - Returns: The record.
    /// - Throws: The error reading the fixture.
    private func execRecord() throws -> [String: Any] {
        try esloggerExec(parent: (401, 4010), env: ["PATH=/usr/bin:/bin"])
    }
    
    /// eslogger's fork of pid 4243 by the exit fixture's process (`/usr/libexec/exampled`, pid 4242).
    ///
    /// - Returns: The record.
    /// - Throws: The error reading the fixture, or an `XCTest` failure if it has no process.
    private func forkRecord() throws -> [String: Any] {
        let process = try XCTUnwrap(try fixtureObject("eslogger-exit.jsonl")["process"] as? [String: Any])
        var child = process
        child["audit_token"] = esloggerToken(pid: 4243, pidversion: 4244)
        child["ppid"] = 4242
        child["original_ppid"] = 4242
        child["parent_audit_token"] = process["audit_token"]
        return try esloggerRecord("fork", type: Int(ES_EVENT_TYPE_NOTIFY_FORK.rawValue), ["child": child])
    }
    
    /// A value's JSON object, as an export writes it.
    ///
    /// - Parameter launchedByParent: The launched-by parent.
    /// - Returns: Its object.
    /// - Throws: The encoder's error, or an `XCTest` failure if it isn't an object.
    private func object(_ launchedByParent: LaunchedByParent) throws -> [String: Any] {
        try XCTUnwrap(try JSONSerialization.jsonObject(with: JSONEncoder().encode(launchedByParent)) as? [String: Any])
    }
    
    /// An exec's and a fork's launched-by parents are exported beside eslogger's fields, as their own JSON.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export lacks one.
    func testExportsTheLaunchedByParent() throws {
        var exec = try importRecord(try execRecord())
        exec.setLaunchedByParent(shellAnswer)
        let exported = try XCTUnwrap(try event("exec", in: try export(exec))["launched_by_parent"] as? [String: Any])
        assertContains(try object(shellAnswer), exported, "exec")
        XCTAssertEqual(Set(exported.keys), Set(try object(shellAnswer).keys))
        
        var fork = try importRecord(try forkRecord())
        fork.resolveLaunchedByParent(by: .import) { _, _ in nil }
        let answer = try XCTUnwrap(fork.createdLaunchedByParent)
        XCTAssertEqual(answer.path, "/usr/libexec/exampled", "the forking process's executable")
        let forkExport = try XCTUnwrap(try event("fork", in: try export(fork))["launched_by_parent"] as? [String: Any])
        assertContains(try object(answer), forkExport, "fork")
    }
    
    /// Every key path and value eslogger wrote is still in the export.
    ///
    /// - Throws: The error reading a record.
    func testEsloggerFieldsAreUnchanged() throws {
        for (record, name) in [(try execRecord(), "exec"), (try forkRecord(), "fork")] {
            var message = try importRecord(record)
            message.resolveLaunchedByParent(by: .import) { _, _ in "/bin/zsh" }
            XCTAssertNotNil(message.createdLaunchedByParent, name)
            assertContains(record, try export(message), ignoring: Self.esloggerSequenceNumbers, name)
        }
    }
    
    /// The stored exec and fork keep their launched-by parent, and can be given another or none.
    ///
    /// - Throws: The error reading a record.
    func testStoredLaunchedByParent() throws {
        var exec = try importRecord(try execRecord())
        exec.setLaunchedByParent(shellAnswer)
        let job = LaunchedByParent(source: .launchdJob, audit_token: .fixture(pid: 1, pidversion: 1),
                                   path: LaunchedByParent.launchdPath, launchd_job: .init(label: "com.example.agent"),
                                   resolved_by: .securityExtension)
        withStoredEvent(exec) { stored in
            let event = stored.event.exec
            XCTAssertEqual(event?.launched_by_parent, shellAnswer)
            event?.launched_by_parent = job
            XCTAssertEqual(event?.launched_by_parent, job)
            let byPID = LaunchedByParent(source: .unixParent, audit_token: nil, pid: 401, path: nil, resolved_by: .app)
            event?.launched_by_parent = byPID
            XCTAssertEqual(event?.launched_by_parent, byPID, "a parent known by pid only")
            event?.launched_by_parent = nil
            XCTAssertNil(event?.launched_by_parent)
            let columns: [Any?] = [event?.launched_by_parent_source, event?.launched_by_parent_resolved_by,
                                   event?.launched_by_parent_pid, event?.launched_by_parent_path,
                                   event?.launched_by_parent_job, event?.launched_by_parent_token]
            XCTAssertTrue(columns.allSatisfy { $0 == nil })
        }
        var fork = try importRecord(try forkRecord())
        fork.setLaunchedByParent(job)
        XCTAssertEqual(withStoredEvent(fork) { $0.event.fork?.launched_by_parent }, job)
    }
    
    /// A token's column keeps all eight of its values, whatever their size, and nothing else reads as a token.
    func testTokenColumnKeepsEveryValue() {
        let token = AuditToken(pid: 99_998, pidversion: Int32.max, asid: 100_017, auid: 4_294_967_295, euid: 501,
                               ruid: 502, rgid: 20, egid: 4_294_967_294)
        XCTAssertEqual(token.columnData.count, AuditToken.columnSize)
        XCTAssertEqual(AuditToken(columnData: token.columnData), token)
        XCTAssertNil(AuditToken(columnData: token.columnData.dropLast()))
        XCTAssertNil(AuditToken(columnData: Data()))
    }
    
    /// An exec or fork without a launched-by parent exports `"launched_by_parent": null`: the key is always there.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export lacks the key.
    func testWithoutOneExportsNull() throws {
        for (record, name) in [(try execRecord(), "exec"), (try forkRecord(), "fork")] {
            let message = try importRecord(record)
            XCTAssertNil(message.createdLaunchedByParent, name)
            XCTAssertTrue(try event(name, in: try export(message))["launched_by_parent"] is NSNull, name)
            XCTAssertTrue(exportText(message).contains(#""launched_by_parent":null"#), name)
        }
    }
}
