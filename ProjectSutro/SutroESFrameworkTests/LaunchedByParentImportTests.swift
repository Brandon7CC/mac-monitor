//
//  LaunchedByParentImportTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Launched-by parents of opened traces
/// Pins how a trace that doesn't carry launched-by parents (eslogger's, Mac Monitor 2.1's) gets them when it's opened:
/// from its own fields, naming paths only from the trace, in file order, and keeping any it carries.
final class LaunchedByParentImportTests: XCTestCase {
    /// Synthetic eslogger execs and forks, one per shape of launch, in file order.
    private static let lineageFixture = "eslogger-lineage.jsonl"
    
    /// What a record's launched-by parent should be.
    private struct Expected {
        let source: LaunchedByParent.Source
        let pid: Int32
        let pidversion: Int32?
        let path: String?
        let label: String?
    }
    
    /// The fixture's records read as File > Open Trace… reads them.
    ///
    /// - Returns: The events, in file order.
    /// - Throws: The error reading the fixture.
    private func lineageMessages() throws -> [Message] {
        try fixtureRecords(Self.lineageFixture).map { try importRecord($0) }
    }
    
    /// Every exec and fork of the fixture, in order, gets the answer its shape calls for.
    ///
    /// - Throws: The error reading the fixture, or an `XCTest` failure if an event has no answer.
    func testLineageFixture() throws {
        var messages = try lineageMessages()
        XCTAssertTrue(messages.allSatisfy { $0.createdLaunchedByParent == nil }, "eslogger carries none")
        TraceLaunchedByParents().fill(&messages)
        let launchdJob = { (label: String) in
            Expected(source: .launchdJob, pid: 1, pidversion: 1, path: LaunchedByParent.launchdPath, label: label)
        }
        let expected: [Expected] = [
            Expected(source: .unixParent, pid: 401, pidversion: 4010, path: "/bin/zsh", label: nil),
            Expected(source: .unixParent, pid: 401, pidversion: 4010, path: "/bin/zsh", label: nil),
            Expected(source: .unixParent, pid: 1, pidversion: 1, path: LaunchedByParent.launchdPath, label: nil),
            Expected(source: .unixParent, pid: 1, pidversion: 1, path: LaunchedByParent.launchdPath, label: nil),
            launchdJob("com.example.agent"),
            launchdJob(Self.lineageAppLabel),
            Expected(source: .responsibleProcess, pid: 500, pidversion: 5000,
                     path: "/Applications/Example.app/Contents/MacOS/Example", label: "com.example.App.ExampleService"),
            Expected(source: .unixParent, pid: 401, pidversion: nil, path: nil, label: nil),
            Expected(source: .unixParent, pid: 1, pidversion: 1, path: LaunchedByParent.launchdPath, label: nil),
            Expected(source: .unixParent, pid: 410, pidversion: 4102, path: "/usr/libexec/exampled", label: nil),
        ]
        XCTAssertEqual(messages.count, expected.count)
        for (index, (message, want)) in zip(messages, expected).enumerated() {
            let line = "line \(index + 1)"
            let answer = try XCTUnwrap(message.createdLaunchedByParent, line)
            XCTAssertEqual(answer.source, want.source, line)
            XCTAssertEqual(answer.pid, want.pid, line)
            XCTAssertEqual(answer.audit_token?.pidversion, want.pidversion, line)
            XCTAssertEqual(answer.path, want.path, line)
            XCTAssertEqual(answer.launchd_job?.label, want.label, line)
            XCTAssertEqual(answer.resolved_by, .import, line)
        }
        XCTAssertTrue(try XCTUnwrap(messages[5].createdLaunchedByParent).needsLaunchServices)
    }
    
    /// Forks name their parent, the forking process, by its executable.
    ///
    /// - Throws: The error reading the fixture.
    func testForksAreNamedByTheForkingProcess() throws {
        var forks = try lineageMessages().filter { $0.event_type == Int(ES_EVENT_TYPE_NOTIFY_FORK.rawValue) }
        TraceLaunchedByParents().fill(&forks)
        XCTAssertEqual(forks.map { $0.createdLaunchedByParent?.source }, [.unixParent, .unixParent])
        XCTAssertEqual(forks.map { $0.createdLaunchedByParent?.path }, ["/bin/zsh", LaunchedByParent.launchdPath])
    }
    
    /// A parent's path comes only from an earlier event of the same process image: not from the same pid with
    /// another pid version, and not from this Mac, even for a live process.
    ///
    /// - Throws: The error reading a record.
    func testPathsComeOnlyFromTheSameProcessInTheTrace() throws {
        var records = try fixtureRecords(Self.lineageFixture)
        var shell = try XCTUnwrap(records[0]["process"] as? [String: Any])
        shell["audit_token"] = esloggerToken(pid: 401, pidversion: 4011)
        records[0]["process"] = shell
        var messages = try records[0...1].map { try importRecord($0) }
        TraceLaunchedByParents().fill(&messages)
        XCTAssertEqual(messages[1].createdLaunchedByParent?.audit_token?.pidversion, 4010)
        XCTAssertNil(messages[1].createdLaunchedByParent?.path, "pid 401 had another pid version")
        
        var live = [try importRecord(try esloggerExec(parent: (Int(getpid()), 1)))]
        TraceLaunchedByParents().fill(&live)
        XCTAssertEqual(live[0].createdLaunchedByParent?.pid, getpid())
        XCTAssertNil(live[0].createdLaunchedByParent?.path, "never read from this Mac")
    }
    
    /// A trace read in batches names a parent seen in an earlier batch.
    ///
    /// - Throws: The error reading the fixture.
    func testBatchesShareTheirMemory() throws {
        let messages = try lineageMessages()
        let launchedByParents = TraceLaunchedByParents()
        var first = Array(messages[..<5]), second = Array(messages[5...])
        launchedByParents.fill(&first)
        launchedByParents.fill(&second)
        XCTAssertEqual(second.last?.createdLaunchedByParent?.path, "/usr/libexec/exampled")
        
        var alone = Array(messages[5...])
        TraceLaunchedByParents().fill(&alone)
        XCTAssertNil(alone.last?.createdLaunchedByParent?.path, "the job's exec wasn't seen")
    }
    
    /// Mac Monitor 2.1's export of an exec gets an answer the same way: a job's program, exec'd by `xpcproxy`.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if the fixture has no exec.
    func testMacMonitor21Exec() throws {
        let record = try fixtureRecords(Self.lineageFixture)[4]
        let exec = try XCTUnwrap((record["event"] as? [String: Any])?["exec"])
        let legacy = try execedByXPCProxy(try legacyRecord("exec", type: ES_EVENT_TYPE_NOTIFY_EXEC, exec))
        var messages = [try importRecord(legacy)]
        TraceLaunchedByParents().fill(&messages)
        let answer = try XCTUnwrap(messages[0].createdLaunchedByParent)
        XCTAssertEqual(answer.source, .launchdJob)
        XCTAssertEqual(answer.launchd_job?.label, "com.example.agent")
        XCTAssertEqual(answer.resolved_by, .import)
    }
    
    /// A launched-by parent the trace carries (Mac Monitor 2.2's LaunchServices answer, which can't be worked out
    /// again) is kept as it is.
    ///
    /// - Throws: The error reading a record or encoding the answer.
    func testCarriedLaunchedByParentIsKept() throws {
        let finder = LaunchedByParent(source: .launchServices, audit_token: .fixture(pid: 600, pidversion: 6000),
                                      path: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
                                      launchd_job: .init(label: Self.lineageAppLabel), resolved_by: .app)
        var record = try fixtureRecords(Self.lineageFixture)[5]
        var event = try XCTUnwrap(record["event"] as? [String: Any])
        var exec = try XCTUnwrap(event["exec"] as? [String: Any])
        exec["launched_by_parent"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(finder))
        event["exec"] = exec
        record["event"] = event
        var messages = [try importRecord(record)]
        XCTAssertEqual(messages[0].createdLaunchedByParent, finder)
        TraceLaunchedByParents().fill(&messages)
        XCTAssertEqual(messages[0].createdLaunchedByParent, finder)
    }
    
    /// Events that create no process are left as they are.
    ///
    /// - Throws: The error reading the fixtures.
    func testOtherEventsAreUntouched() throws {
        var messages = try fixtureRecords("eslogger-open.jsonl").map { try importRecord($0) }
            + [try importRecord(try fixtureObject("eslogger-exit.jsonl"))]
        let before = try messages.map { try JSONCanonicalForm.canonical(try JSONEncoder().encode($0)) }
        TraceLaunchedByParents().fill(&messages)
        XCTAssertEqual(try messages.map { try JSONCanonicalForm.canonical(try JSONEncoder().encode($0)) }, before)
    }
}
