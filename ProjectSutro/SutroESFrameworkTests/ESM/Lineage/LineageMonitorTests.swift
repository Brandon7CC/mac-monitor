//
//  LineageMonitorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Feeding the lineage table
/// Pins how the Security Extension keeps its lineage table told: what a fork, an exec and an exit message change,
/// that a program's values are its exec record's, what's read of the processes already running, and how the
/// monitor's own Endpoint Security client is started and stopped.
final class LineageMonitorTests: XCTestCase {
    /// A key.
    ///
    /// - Parameters:
    ///   - pid: The pid.
    ///   - version: The pid version.
    /// - Returns: The key.
    private func key(_ pid: Int32, _ version: Int32) -> ProcessKey {
        ProcessKey(pid: pid, pidversion: version)
    }

    /// An audit token.
    ///
    /// - Parameters:
    ///   - pid: The pid.
    ///   - version: The pid version.
    /// - Returns: The token.
    private func token(_ pid: Int32, _ version: UInt32) -> audit_token_t {
        RawMessageFixture.auditToken(pid: pid, pidversion: version)
    }

    /// A fork message: a process forks a child.
    ///
    /// - Parameters:
    ///   - parent: The forking process.
    ///   - child: The child.
    /// - Returns: The message.
    private func fork(by parent: audit_token_t, of child: audit_token_t) -> RawMessageFixture {
        let message = rawMessage(type: ES_EVENT_TYPE_NOTIFY_FORK)
        let forked = message.fork(childPID: 0, parent: parent, responsible: parent)
        forked.pointee.audit_token = child
        return message
    }

    /// An exec message: a process execs a program.
    ///
    /// - Parameters:
    ///   - process: The process, before the exec.
    ///   - target: The program it execs.
    /// - Returns: The message.
    private func exec(by process: audit_token_t, of target: UnsafeMutablePointer<es_process_t>) -> RawMessageFixture {
        let message = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXEC)
        message.message.pointee.process.pointee.audit_token = process
        message.message.pointee.event.exec.target = target
        return message
    }

    /// A fork, an exec and an exit change the table as Endpoint Security reported them, and another event changes
    /// nothing.
    func testMessagesChangeTheTable() {
        let lineage = ProcessLineage()
        lineage.seed([(ProcessProgram(key: key(100, 1), path: "/bin/zsh"), 1)])
        lineage.note(fork(by: token(100, 1), of: token(200, 2)).message, at: 0)
        XCTAssertEqual(lineage.program(key(200, 2))?.path, "/bin/zsh")

        let holder = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXEC)
        let target = holder.process(path: "/usr/bin/true", signingID: "com.apple.true", teamID: nil)
        target.pointee.audit_token = token(200, 3)
        target.pointee.parent_audit_token = token(100, 1)
        lineage.note(exec(by: token(200, 2), of: target).message, at: 0) { _ in ["true", "", "spawned "] }
        XCTAssertEqual(lineage.program(key(200, 3)),
                       ProcessProgram(key: key(200, 3), path: "/usr/bin/true", commandLine: "true  spawned",
                                      signingID: "com.apple.true", teamID: nil, codesigningType: "PLATFORM"))
        XCTAssertEqual(lineage.ancestors(of: key(200, 3)).map(\.path), ["/bin/zsh"])

        let other = rawMessage(type: ES_EVENT_TYPE_NOTIFY_SIGNAL)
        other.message.pointee.process.pointee.audit_token = token(200, 3)
        lineage.note(other.message, at: 50)
        XCTAssertNotNil(lineage.program(key(200, 3)))

        let exit = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
        exit.message.pointee.process.pointee.audit_token = token(200, 3)
        lineage.note(exit.message, at: 50)
        XCTAssertNotNil(lineage.program(key(200, 3)), "It lingers")
        lineage.note(exit.message, at: 50 + ProcessLineage.lingers)
        XCTAssertNil(lineage.program(key(200, 3)))
    }

    /// An exec of a process the table never saw fork takes the parent the exec names.
    func testAnExecNamesItsParent() {
        let lineage = ProcessLineage()
        lineage.seed([(ProcessProgram(key: key(100, 1), path: "/bin/zsh"), 1)])
        let holder = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXEC)
        let target = holder.process(path: "/usr/bin/true")
        target.pointee.audit_token = token(300, 9)
        target.pointee.parent_audit_token = token(100, 1)
        lineage.note(exec(by: token(300, 8), of: target).message, at: 0) { _ in [] }
        XCTAssertEqual(lineage.ancestors(of: key(300, 9)).map(\.path), ["/bin/zsh"])
        XCTAssertEqual(lineage.program(key(300, 9))?.commandLine, "")
    }

    /// A program's path, signing ID, team ID and code signing type are the ones its process's record has, however
    /// it's signed: a platform binary, adhoc, unsigned, and validly signed by a certificate that's read.
    func testAProgramHasItsRecordsValues() {
        let holder = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXEC)
        let signed = UInt32(CS_VALID), adhoc = UInt32(CS_VALID | CS_ADHOC)
        let cases: [(path: String, signingID: String?, teamID: String?, flags: UInt32, platform: Bool)] = [
            ("/usr/bin/true", "com.apple.true", nil, signed, true), ("/tmp/adhoc", "adhoc-1", "", adhoc, false),
            ("/tmp/unsigned", nil, nil, 0, false),
            ("/tmp/no/such/developer-id", "com.example", "TEAM123", signed, false),
            ("/bin/zsh", "com.apple.zsh", nil, signed, false),
        ]
        for example in cases {
            let process = holder.process(path: example.path, signingID: example.signingID, teamID: example.teamID,
                                         flags: example.flags, platform: example.platform, pid: 77)
            let record = SutroESFramework.Process(from: process.pointee, version: 10)
            let program = ProcessProgram(process.pointee, arguments: ["a", "b"])
            XCTAssertEqual(program.path, record.executable?.path, example.path)
            XCTAssertEqual(program.signingID, record.signing_id, example.path)
            XCTAssertEqual(program.teamID, record.team_id, example.path)
            XCTAssertEqual(program.codesigningType, record.codesigning_type.rawValue, example.path)
            XCTAssertEqual(program.key, record.audit_token.map(ProcessKey.init), example.path)
            XCTAssertEqual(program.commandLine, "a b")
        }
        XCTAssertEqual(Set(cases.map { ProcessProgram.codesigningType(of: holder.process(
            path: $0.path, flags: $0.flags, platform: $0.platform).pointee) }).count, 4)
    }

    /// The arguments are read from what the kernel returns for a process: a count, the executable's path, padding,
    /// then each argument. The environment after them isn't taken for arguments.
    func testReadingAProcessesArguments() {
        var bytes = withUnsafeBytes(of: Int32(3)) { Array($0) }
        bytes += Array("/usr/bin/tool".utf8) + [0, 0, 0, 0]
        for text in ["tool", "", "--flag value", "HOME=/var/root", "PATH=/usr/bin"] { bytes += Array(text.utf8) + [0] }
        XCTAssertEqual(RunningProcesses.arguments(in: bytes), ["tool", "", "--flag value"])
        XCTAssertEqual(RunningProcesses.arguments(in: bytes.prefix(25)), ["tool"], "Cut off after an argument")
        XCTAssertEqual(RunningProcesses.arguments(in: withUnsafeBytes(of: Int32(2)) { Array($0) } + [47, 0]), [])
        XCTAssertNil(RunningProcesses.arguments(in: [1, 0, 0]))
        XCTAssertNil(RunningProcesses.arguments(in: [UInt8]()))
    }

    /// The running processes include this one, with its own key, its parent, its executable and its arguments, and
    /// neither launchd nor the kernel.
    func testTheRunningProcessesIncludeThisOne() throws {
        let running = RunningProcesses.read(signatures: false)
        let own = ProcessKey(audit_token_t.currentProcess)
        let this = try XCTUnwrap(running.first { $0.program.key == own })
        XCTAssertEqual(this.parent, getppid())
        XCTAssertEqual(this.program.path, ProcessPath.live(getpid(), nil))
        XCTAssertEqual(this.program.commandLine,
                       ProcessProgram.commandLine(ProcessInfo.processInfo.arguments))
        XCTAssertNil(this.program.signingID)
        XCTAssertFalse(running.contains { $0.program.key.pid <= 1 })
        XCTAssertGreaterThan(running.count, 10)
        XCTAssertNotNil(RunningProcesses.signature(of: audit_token_t.currentProcess))
        XCTAssertNil(RunningProcesses.token(of: -5))
    }

    /// The first capture session to hold the monitor starts it: one client, which mutes the Security Extension
    /// itself, subscribes to fork, exec and exit, then adds the running processes. Its messages reach the table. A
    /// second session shares the client. Only when the last lets go is the client deleted and the table emptied,
    /// and the next session starts it afresh.
    func testCaptureSessionsShareIt() {
        let factory = FakeEndpointSecurityClientFactory()
        let shell = ProcessProgram(key: key(100, 1), path: "/bin/zsh")
        let monitor = LineageMonitor(lineage: ProcessLineage(), factory: factory, clock: { 0 },
                                     running: { [(program: shell, parent: Int32(1), token: nil)] },
                                     arguments: { _ in [] })
        XCTAssertFalse(monitor.isRunning)
        XCTAssertNil(monitor.table)
        let seeded = expectation(description: "Seeded")
        XCTAssertNil(monitor.acquire { seeded.fulfill() })
        wait(for: [seeded], timeout: 10)
        XCTAssertTrue(monitor.isRunning)
        XCTAssertTrue(monitor.table === monitor.lineage)
        XCTAssertEqual(factory.clients.count, 1)
        let client = factory.clients[0]
        XCTAssertEqual(client.calls(.muteProcess).count, 1)
        XCTAssertEqual(client.calls(.subscribe), [.subscribe(LineageMonitor.events)])
        XCTAssertEqual(monitor.lineage.program(key(100, 1))?.path, "/bin/zsh")

        client.deliver(fork(by: token(100, 1), of: token(200, 2)))
        XCTAssertEqual(monitor.lineage.ancestors(of: key(200, 2)).map(\.path), ["/bin/zsh"])

        XCTAssertNil(monitor.acquire())
        XCTAssertEqual(factory.clients.count, 1)
        monitor.release()
        XCTAssertTrue(monitor.isRunning, "One session still captures")
        XCTAssertEqual(monitor.lineage.count, 2)
        monitor.release()
        XCTAssertFalse(monitor.isRunning)
        XCTAssertNil(monitor.table)
        XCTAssertEqual(client.calls(.delete).count, 1)
        XCTAssertEqual(monitor.lineage.count, 0, "What it held would go stale")
        monitor.release()

        let again = expectation(description: "Seeded again")
        XCTAssertNil(monitor.acquire { again.fulfill() })
        wait(for: [again], timeout: 10)
        XCTAssertEqual(factory.clients.count, 2)
        XCTAssertEqual(monitor.lineage.program(key(100, 1))?.path, "/bin/zsh")
        XCTAssertNil(monitor.lineage.program(key(200, 2)))
        monitor.release()
    }

    /// Asking whether it runs, or for its table, never waits on Endpoint Security. The network client asks from
    /// queues that mustn't wait while a capture session starts or stops the monitor.
    func testAskingNeverWaitsOnEndpointSecurity() {
        let factory = FakeEndpointSecurityClientFactory()
        let subscribing = DispatchSemaphore(value: 0), gate = DispatchSemaphore(value: 0)
        factory.onSubscribe = { _, _ in
            subscribing.signal()
            gate.wait()
        }
        let monitor = LineageMonitor(lineage: ProcessLineage(), factory: factory, running: { [] })
        DispatchQueue.global().async { monitor.acquire() }
        XCTAssertEqual(subscribing.wait(timeout: .now() + 5), .success)
        let answered = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            if !monitor.isRunning, monitor.table == nil { answered.signal() }
        }
        XCTAssertEqual(answered.wait(timeout: .now() + 1), .success, "Answered while the client subscribes")
        gate.signal()
        XCTAssertTrue(waitUntil { monitor.isRunning })
        XCTAssertTrue(monitor.table === monitor.lineage)
        monitor.release()
        XCTAssertNil(monitor.table)
    }

    /// A client Endpoint Security refuses, or one that can't subscribe, leaves the monitor stopped, and says why.
    func testAClientThatIsRefused() {
        let refused = LineageMonitor(lineage: ProcessLineage(),
                                     factory: FakeEndpointSecurityClientFactory(refusals: [0: .tooManyClients]),
                                     running: { [] })
        XCTAssertEqual(refused.acquire(), .tooManyClients)
        XCTAssertFalse(refused.isRunning)
        XCTAssertNil(refused.table)
        refused.release()

        let factory = FakeEndpointSecurityClientFactory(refusing: [0: [.subscribe]])
        let deaf = LineageMonitor(lineage: ProcessLineage(), factory: factory, running: { [] })
        XCTAssertEqual(deaf.acquire(), .internalSubsystem)
        XCTAssertFalse(deaf.isRunning)
        XCTAssertEqual(factory.clients[0].calls(.delete).count, 1)
    }
}
