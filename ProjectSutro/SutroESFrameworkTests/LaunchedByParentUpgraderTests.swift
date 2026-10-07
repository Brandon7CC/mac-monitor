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
/// Tests which execs the Security Extension holds for Launch Services, how often it asks, and what it gets back. Also
/// checks that a lane's events still leave in order.
final class LaunchedByParentUpgraderTests: XCTestCase {
    /// An app's label, as launchd names a LaunchServices instance.
    private let label = XCTestCase.lineageAppLabel
    /// The process that asked LaunchServices to launch the apps.
    private let launcher = AuditToken(pid: 700, pidversion: 7000, asid: 100_001, auid: 501, euid: 501, ruid: 501,
                                      rgid: 20, egid: 20)
    /// eslogger's exec of `/usr/libexec/exampled` by launchd, which the apps' execs are made from.
    private var exec: Message!
    /// Events the hold sent, in order
    private let emitted = OSAllocatedUnfairLock(uncheckedState: [CapturedEvent]())

    /// Read the exec the apps' execs are made from.
    ///
    /// - Throws: The error reading the exec.
    override func setUpWithError() throws {
        exec = try importRecord(try esloggerExec(parent: (1, 1)))
    }

    /// What the Security Extension first says about an app: launchd started the app's job.
    private var appJob: LaunchedByParent {
        LaunchedByParent(source: .launchdJob, audit_token: .fixture(pid: 1, pidversion: 1),
                         path: LaunchedByParent.launchdPath, launchd_job: .init(label: label),
                         resolved_by: .securityExtension)
    }

    /// Launch Services' answer for an app that ``launcher`` launched
    private var launchedByLauncher: LaunchedByParent {
        LaunchedByParent(source: .launchServices, audit_token: launcher, path: "/path/of/700",
                         launchd_job: .init(label: label), resolved_by: .securityExtension)
    }

    /// An app's exec as the lane built it
    ///
    /// - Parameters:
    ///   - pid: The app's pid. Its pid version is ten times that.
    ///   - answer: Its launched-by parent, by default ``appJob``.
    /// - Returns: The event.
    private func appExec(pid: Int32, answer: LaunchedByParent? = nil) -> Message {
        var message = exec!
        if case .exec(var event) = message.event {
            event.target.pid = pid
            event.target.audit_token = AuditToken(pid: pid, pidversion: pid * 10, asid: 100_001, auid: 501, euid: 501,
                                                  ruid: 501, rgid: 20, egid: 20)
            message.event = .exec(event)
        }
        message.setLaunchedByParent(answer ?? appJob)
        message.id = UUID()
        return message
    }

    /// The target token of an exec from ``appExec(pid:answer:)``
    ///
    /// - Parameter pid: The app's pid.
    /// - Returns: The token.
    private func target(_ pid: Int32) -> AuditToken {
        AuditToken(pid: pid, pidversion: pid * 10, asid: 100_001, auid: 501, euid: 501, ruid: 501, rgid: 20, egid: 20)
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
    /// - Parameter reader: Its reader.
    /// - Returns: The upgrader.
    private func upgrader(_ reader: FakeLaunchServicesReader) -> LaunchedByParentUpgrader {
        LaunchedByParentUpgrader(reader: reader, delays: [0, 0.01, 0.02]) { pid, _ in "/path/of/\(pid)" }
    }

    /// Look up who launched an app and wait for the answer.
    ///
    /// - Parameters:
    ///   - pid: The app's pid.
    ///   - reader: The reader.
    /// - Returns: What the lookup returned.
    private func lookUp(pid: Int32, with reader: FakeLaunchServicesReader) -> LaunchedByParent? {
        let done = expectation(description: "Lookup finished")
        let answer = OSAllocatedUnfairLock<LaunchedByParent?>(uncheckedState: nil)
        upgrader(reader).lookUp(appJob, of: target(pid)) { better in
            answer.withLockUnchecked { $0 = better }
            done.fulfill()
        }
        wait(for: [done], timeout: 5)
        return answer.withLockUnchecked { $0 }
    }

    /// A hold for the process lane that sends into ``emitted``
    ///
    /// - Parameters:
    ///   - reader: The reader.
    ///   - maxHeld: The most execs held at a time.
    /// - Returns: The hold.
    private func hold(_ reader: FakeLaunchServicesReader, maxHeld: Int = 64) -> LaunchServicesHold {
        LaunchServicesHold(eventClass: .process, upgrader: upgrader(reader), maxHeld: maxHeld) { event in
            self.emitted.withLockUnchecked { $0.append(event) }
        }
    }

    /// A ready event whose JSON is just its name
    ///
    /// - Parameter name: The name.
    /// - Returns: The event.
    private func ready(_ name: String) -> CapturedEvent {
        CapturedEvent(json: Data(name.utf8), eventClass: .process)
    }

    /// What the hold sent. Ready events show their name, and execs show `exec <pid>` with their launched-by parent.
    private var emittedEvents: [(name: String, launchedByParent: LaunchedByParent?)] {
        emitted.withLockUnchecked { $0 }.map { event in
            guard let message = try? JSONDecoder().decode(Message.self, from: event.json),
                  case .exec(let exec) = message.event else { return (String(decoding: event.json, as: UTF8.self), nil) }
            return ("exec \(exec.target.pid)", exec.launched_by_parent)
        }
    }

    /// Wait until the hold has sent this many events.
    ///
    /// - Parameters:
    ///   - count: The number of events.
    ///   - line: The caller's line, for a failure.
    private func waitForEmitted(_ count: Int, line: UInt = #line) {
        let deadline = Date(timeIntervalSinceNow: 5)
        while emitted.withLockUnchecked({ $0.count }) < count, Date() < deadline { usleep(2_000) }
        XCTAssertEqual(emitted.withLockUnchecked { $0.count }, count, line: line)
    }

    // MARK: Which execs are held

    /// Only app execs with a target token are held. Forks, other events, Unix parents, non-app launchd jobs and execs
    /// without an answer go straight through.
    ///
    /// - Throws: The error reading a record.
    func testOnlyAppExecsAreHeld() throws {
        var fork = try importRecord(try esloggerRecord("fork", type: Int(ES_EVENT_TYPE_NOTIFY_FORK.rawValue), [
            "child": try XCTUnwrap(try fixtureObject("eslogger-exit.jsonl")["process"] as? [String: Any]),
        ]))
        fork.setLaunchedByParent(appJob)
        let exit = try importRecord(try fixtureObject("eslogger-exit.jsonl"))
        var unixParent = appJob, agent = appJob
        unixParent.source = .unixParent
        agent.launchd_job = .init(label: "com.example.agent")
        var unanswered = appExec(pid: 603)
        unanswered.setLaunchedByParent(nil)

        for message in [fork, exit, appExec(pid: 601, answer: unixParent), appExec(pid: 602, answer: agent),
                        unanswered] {
            XCTAssertFalse(LaunchServicesHold.holds(message))
        }
        XCTAssertTrue(LaunchServicesHold.holds(appExec(pid: 606)))
    }

    // MARK: Lookups

    /// A record that shows up on the second read ends the lookup with the launcher.
    func testRecordOnTheSecondReadIsTheAnswer() {
        let reader = FakeLaunchServicesReader { pid, attempt in attempt == 0 ? nil : self.launch(of: pid) }
        XCTAssertEqual(lookUp(pid: 606, with: reader), launchedByLauncher)
        XCTAssertEqual(reader.askedPIDs, [606, 606])
    }

    /// A record of another exec of the app's pid ends the lookup without an answer.
    func testRecordOfAnotherExecEndsTheLookup() {
        let reader = FakeLaunchServicesReader { pid, _ in self.launch(of: pid, pidversion: pid * 10 + 1) }
        XCTAssertNil(lookUp(pid: 606, with: reader))
        XCTAssertEqual(reader.askedPIDs, [606])
    }

    /// Without a record by the last delay, the lookup ends without an answer.
    func testNoRecordIsGivenUpAfterTheLastRead() {
        let reader = FakeLaunchServicesReader()
        XCTAssertNil(lookUp(pid: 606, with: reader))
        XCTAssertEqual(reader.askedPIDs, [606, 606, 606])
    }

    // MARK: The hold

    /// With nothing held, an event goes out right away.
    func testNothingHeldEmitsAtOnce() {
        hold(FakeLaunchServicesReader()).submit(ready("fork"))
        XCTAssertEqual(emittedEvents.map(\.name), ["fork"])
    }

    /// A held exec goes out once with Launch Services' answer, and the events behind it follow in order.
    func testHeldExecLeavesFirstWithItsAnswer() {
        let reader = FakeLaunchServicesReader { pid, attempt in attempt == 0 ? nil : self.launch(of: pid) }
        let hold = hold(reader)
        hold.hold(appExec(pid: 606))
        hold.submit(ready("fork"))
        hold.submit(ready("exit"))
        XCTAssertTrue(emittedEvents.isEmpty, "The events behind a held exec wait")

        waitForEmitted(3)
        XCTAssertEqual(emittedEvents.map(\.name), ["exec 606", "fork", "exit"])
        XCTAssertEqual(emittedEvents.first?.launchedByParent, launchedByLauncher)
    }

    /// Held execs leave in the order they arrived, no matter which lookup finishes first.
    func testHeldExecsLeaveInOrder() {
        let reader = FakeLaunchServicesReader { pid, attempt in
            pid == 606 && attempt < 2 ? nil : self.launch(of: pid)
        }
        let hold = hold(reader)
        hold.hold(appExec(pid: 606))
        hold.submit(ready("fork"))
        hold.hold(appExec(pid: 607))

        waitForEmitted(3)
        XCTAssertEqual(emittedEvents.map(\.name), ["exec 606", "fork", "exec 607"])
        XCTAssertEqual(emittedEvents.compactMap(\.launchedByParent).map(\.source), [.launchServices, .launchServices])
    }

    /// When Launch Services has no record, the exec goes out with the answer it had.
    func testExecWithoutRecordKeepsItsAnswer() {
        let hold = hold(FakeLaunchServicesReader())
        hold.hold(appExec(pid: 606))
        waitForEmitted(1)
        XCTAssertEqual(emittedEvents.first?.launchedByParent, appJob)
    }

    /// Past the limit, an exec isn't held. It goes in line with the answer it has.
    func testExecsPastTheBoundAreNotHeld() {
        let reader = FakeLaunchServicesReader { pid, attempt in attempt == 0 ? nil : self.launch(of: pid) }
        let hold = hold(reader, maxHeld: 1)
        hold.hold(appExec(pid: 606))
        hold.hold(appExec(pid: 607))

        waitForEmitted(2)
        XCTAssertEqual(emittedEvents.map(\.name), ["exec 606", "exec 607"])
        XCTAssertEqual(emittedEvents.map(\.launchedByParent), [launchedByLauncher, appJob])
        XCTAssertEqual(reader.askedPIDs.filter { $0 == 607 }, [], "The exec past the bound isn't looked up")
    }

    /// Closing sends every held exec and the events behind it right away. Nothing is sent afterwards, even when a
    /// lookup finishes.
    func testCloseReleasesEverythingAtOnce() {
        let reader = FakeLaunchServicesReader { pid, attempt in attempt == 0 ? nil : self.launch(of: pid) }
        let hold = hold(reader)
        hold.hold(appExec(pid: 606))
        hold.submit(ready("fork"))
        hold.close()
        XCTAssertEqual(emittedEvents.map(\.name), ["exec 606", "fork"])
        XCTAssertEqual(emittedEvents.first?.launchedByParent, appJob)

        hold.submit(ready("late"))
        usleep(50_000)
        XCTAssertEqual(emittedEvents.map(\.name), ["exec 606", "fork"])
    }
}
