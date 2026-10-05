//
//  LaunchedByParentUpgraderTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
import os
@testable import SutroESFramework


// MARK: - A scripted LaunchServices
/// A LaunchServices reader with scripted records, which remembers the pids it was asked about.
private final class FakeLaunchServicesReader: LaunchServicesReading {
    /// The record for a pid, given how many times it was asked about before.
    private let records: (pid_t, Int) -> LaunchServicesRecord?
    /// The pids asked about, in order.
    private let asked = OSAllocatedUnfairLock(uncheckedState: [pid_t]())
    
    /// - Parameter records: The record for a pid, given how many times it was asked about before. By default none.
    init(_ records: @escaping (pid_t, Int) -> LaunchServicesRecord? = { _, _ in nil }) {
        self.records = records
    }
    
    /// The scripted record.
    ///
    /// - Parameter pid: The pid.
    /// - Returns: The record, or `nil`.
    func record(forPID pid: pid_t) -> LaunchServicesRecord? {
        let attempt = asked.withLockUnchecked { asked in
            asked.append(pid)
            return asked.filter { $0 == pid }.count - 1
        }
        return records(pid, attempt)
    }
    
    /// The pids asked about, in order.
    var askedPIDs: [pid_t] {
        asked.withLockUnchecked { $0 }
    }
}


// MARK: - Looking up apps' launchers
/// Pins which execs Mac Monitor asks LaunchServices about after they arrive, how often, and what it hands back.
final class LaunchedByParentUpgraderTests: XCTestCase {
    /// The audit session of eslogger's synthetic processes, which the upgraders here answer for.
    private let session: Int32 = 100_001
    /// An app's label, as launchd names a LaunchServices instance.
    private let label = XCTestCase.lineageAppLabel
    /// The process that asked LaunchServices to launch the apps.
    private let launcher = AuditToken(pid: 700, pidversion: 7000, asid: 100_001, auid: 501, euid: 501, ruid: 501,
                                      rgid: 20, egid: 20)
    /// eslogger's exec of `/usr/libexec/exampled` by launchd, which the apps' execs are made from.
    private var exec: Message!
    /// The answers each upgrader handed back, in order.
    private let applied = OSAllocatedUnfairLock(uncheckedState: [(UUID, LaunchedByParent)]())
    
    /// Read the exec the apps' execs are made from.
    ///
    /// - Throws: The error reading the exec.
    override func setUpWithError() throws {
        exec = try importRecord(try esloggerExec(parent: (1, 1)))
    }
    
    /// The Security Extension's answer for an app: launchd, starting the app's job.
    private var appJob: LaunchedByParent {
        LaunchedByParent(source: .launchdJob, audit_token: .fixture(pid: 1, pidversion: 1),
                         path: LaunchedByParent.launchdPath, launchd_job: .init(label: label),
                         resolved_by: .securityExtension)
    }
    
    /// An app's exec, as it arrived.
    ///
    /// - Parameters:
    ///   - pid: The app's pid. Its pid version is ten times that.
    ///   - asid: The app's audit session.
    ///   - age: How long ago it happened, in seconds.
    ///   - answer: Its launched-by parent, by default ``appJob``.
    /// - Returns: The event.
    private func appExec(pid: Int32, asid: Int32 = 100_001, age: TimeInterval = 0,
                         answer: LaunchedByParent? = nil) -> Message {
        var message = exec!
        if case .exec(var event) = message.event {
            event.target.pid = pid
            event.target.audit_token = AuditToken(pid: pid, pidversion: pid * 10, asid: asid, auid: 501, euid: 501,
                                                  ruid: 501, rgid: 20, egid: 20)
            message.event = .exec(event)
        }
        message.setLaunchedByParent(answer ?? appJob)
        message.id = UUID()
        message.message_darwin_time = Date(timeIntervalSinceNow: -age)
        return message
    }
    
    /// A record of an app's launch by ``launcher``.
    ///
    /// - Parameters:
    ///   - pid: The app's pid.
    ///   - pidversion: The pid version that checked in, by default the app's.
    /// - Returns: The record.
    private func launch(of pid: pid_t, pidversion: Int32? = nil) -> LaunchServicesRecord {
        let token = AuditToken(pid: pid, pidversion: pidversion ?? pid * 10, asid: 100_001, auid: 501, euid: 501,
                               ruid: 501, rgid: 20, egid: 20)
        return LaunchServicesRecord(token: token, launchedByLaunchServices: true, hasParentASN: true,
                                    parentToken: launcher)
    }
    
    /// An upgrader reading at once, 10 and 20 ms later, naming the launcher `/path/of/<pid>`.
    ///
    /// - Parameters:
    ///   - reader: Its reader, if any.
    ///   - maxPending: The most lookups waiting at a time.
    /// - Returns: The upgrader.
    private func upgrader(_ reader: FakeLaunchServicesReader?, maxPending: Int = 64) -> LaunchedByParentUpgrader {
        let upgrader = LaunchedByParentUpgrader(delays: [0, 0.01, 0.02], maxPending: maxPending,
                                                session: session) { pid, _ in "/path/of/\(pid)" }
        upgrader.reader = reader
        return upgrader
    }
    
    /// Look up these events' apps and wait for every lookup to settle.
    ///
    /// - Parameters:
    ///   - messages: The events.
    ///   - upgrader: The upgrader.
    ///   - line: The caller's line, for a failure.
    private func lookUp(_ messages: [Message], with upgrader: LaunchedByParentUpgrader, line: UInt = #line) {
        upgrader.schedule(messages) { id, answer in self.applied.withLockUnchecked { $0.append((id, answer)) } }
        let deadline = Date(timeIntervalSinceNow: 5)
        while upgrader.pendingCount > 0, Date() < deadline { usleep(2_000) }
        XCTAssertEqual(upgrader.pendingCount, 0, "Lookups still waiting", line: line)
    }
    
    /// The answers handed back, in order.
    private var answers: [(id: UUID, launchedByParent: LaunchedByParent)] {
        applied.withLockUnchecked { $0 }.map { (id: $0.0, launchedByParent: $0.1) }
    }
    
    /// Only an exec whose answer needs LaunchServices, whose target is in Mac Monitor's audit session, and that
    /// happened in the last ten seconds is looked up: not a fork, another event, the Unix parent, a launchd job that
    /// isn't an app, an exec without an answer, an app in another session, or one from eleven seconds ago.
    ///
    /// - Throws: The error reading a record.
    func testOnlyFreshAppExecsInThisSessionAreLookedUp() throws {
        var fork = try importRecord(try esloggerRecord("fork", type: Int(ES_EVENT_TYPE_NOTIFY_FORK.rawValue), [
            "child": try XCTUnwrap(try fixtureObject("eslogger-exit.jsonl")["process"] as? [String: Any]),
        ]))
        fork.setLaunchedByParent(appJob)
        fork.message_darwin_time = Date()
        let exit = try importRecord(try fixtureObject("eslogger-exit.jsonl"))
        var unixParent = appJob, agent = appJob
        unixParent.source = .unixParent
        agent.launchd_job = .init(label: "com.example.agent")
        var unanswered = appExec(pid: 603)
        unanswered.setLaunchedByParent(nil)
        let messages = [fork, exit, appExec(pid: 601, answer: unixParent), appExec(pid: 602, answer: agent), unanswered,
                        appExec(pid: 604, asid: 100_002), appExec(pid: 605, age: 11), appExec(pid: 606)]
        
        let reader = FakeLaunchServicesReader()
        lookUp(messages, with: upgrader(reader))
        XCTAssertEqual(reader.askedPIDs, [606, 606, 606])
        XCTAssertTrue(answers.isEmpty)
    }
    
    /// A record that appears on the second read is applied once, with the exec's `id`, and ends the lookup.
    func testRecordOnTheSecondReadIsAppliedOnce() {
        let reader = FakeLaunchServicesReader { pid, attempt in attempt == 0 ? nil : self.launch(of: pid) }
        let app = appExec(pid: 606)
        lookUp([app], with: upgrader(reader))
        
        XCTAssertEqual(reader.askedPIDs, [606, 606])
        XCTAssertEqual(answers.count, 1)
        XCTAssertEqual(answers.first?.id, app.id)
        XCTAssertEqual(answers.first?.launchedByParent,
                       LaunchedByParent(source: .launchServices, audit_token: launcher, path: "/path/of/700",
                                        launchd_job: .init(label: label), resolved_by: .app))
    }
    
    /// A record of another exec of the app's pid ends the lookup without an answer.
    func testRecordOfAnotherExecEndsTheLookup() {
        let reader = FakeLaunchServicesReader { pid, _ in self.launch(of: pid, pidversion: pid * 10 + 1) }
        lookUp([appExec(pid: 606)], with: upgrader(reader))
        XCTAssertEqual(reader.askedPIDs, [606])
        XCTAssertTrue(answers.isEmpty)
    }
    
    /// Without a record by the last delay, the lookup gives up.
    func testNoRecordIsGivenUpAfterTheLastRead() {
        let reader = FakeLaunchServicesReader()
        lookUp([appExec(pid: 606)], with: upgrader(reader))
        XCTAssertEqual(reader.askedPIDs, [606, 606, 606])
        XCTAssertTrue(answers.isEmpty)
    }
    
    /// Past the bound, new lookups are dropped: the 65th app is never asked about.
    func testLookupsPastTheBoundAreDropped() {
        let reader = FakeLaunchServicesReader()
        let apps = (1_000..<1_065).map { appExec(pid: Int32($0)) }
        lookUp(apps, with: upgrader(reader))
        XCTAssertEqual(Set(reader.askedPIDs), Set((1_000..<1_064).map { pid_t($0) }))
        XCTAssertEqual(reader.askedPIDs.count, 64 * 3)
    }
    
    /// Without a reader nothing is looked up, and taking the reader away ends the lookups waiting.
    func testWithoutReaderNothingIsLookedUp() {
        let quiet = upgrader(nil)
        lookUp([appExec(pid: 606)], with: quiet)
        XCTAssertTrue(answers.isEmpty)
        
        let reader = FakeLaunchServicesReader { pid, attempt in attempt == 0 ? nil : self.launch(of: pid) }
        let removed = upgrader(reader)
        removed.schedule([appExec(pid: 607)]) { _, _ in XCTFail("Applied without a reader") }
        removed.reader = nil
        lookUp([], with: removed)
        XCTAssertLessThanOrEqual(reader.askedPIDs.count, 1)
    }
    
    /// Each answer goes with its own exec's `id`, whatever order the records come in.
    func testAnswersGoWithTheirExecs() {
        let reader = FakeLaunchServicesReader { pid, attempt in
            pid == 606 && attempt == 0 ? nil : self.launch(of: pid)
        }
        let first = appExec(pid: 606), second = appExec(pid: 607)
        lookUp([first, second], with: upgrader(reader))
        XCTAssertEqual(answers.map(\.id), [second.id, first.id])
        XCTAssertEqual(Set(answers.map(\.launchedByParent.audit_token)), [launcher])
    }
}
