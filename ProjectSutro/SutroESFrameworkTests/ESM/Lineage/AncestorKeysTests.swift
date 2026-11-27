//
//  AncestorKeysTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Ancestor keys in a record
/// Pins the `ancestor_keys` an exec and a fork record carry: what the Security Extension stamps from its lineage
/// table, whichever of the table's client and the capture lane is ahead, that the keys survive the wire, the export
/// and File > Open Trace, and that a capture session keeps the lineage monitor running only while it captures.
final class AncestorKeysTests: XCTestCase {
    private var lineage = ProcessLineage()

    /// A table that knows sshd and the shell it started.
    override func setUp() {
        super.setUp()
        lineage = ProcessLineage()
        lineage.seed([(ProcessProgram(key: ProcessKey(pid: 50, pidversion: 1), path: "/usr/sbin/sshd"), 1),
                      (ProcessProgram(key: ProcessKey(pid: 100, pidversion: 1), path: "/bin/zsh"), 50)])
    }

    /// The shell's child, before and after its exec.
    ///
    /// - Parameter pidversion: Its pid version.
    /// - Returns: The process, as eslogger writes it.
    /// - Throws: If the fixture can't be read.
    private func child(_ pidversion: Int) throws -> [String: Any] {
        try esloggerProcess(pid: 200, pidversion: pidversion, path: pidversion == 2 ? "/bin/zsh" : "/usr/bin/true",
                            parent: (100, 1))
    }

    /// The shell.
    ///
    /// - Returns: The process, as eslogger writes it.
    /// - Throws: If the fixture can't be read.
    private func parentShell() throws -> [String: Any] {
        try esloggerProcess(pid: 100, pidversion: 1, path: "/bin/zsh", parent: (50, 1))
    }

    /// An event stamped from the test's table.
    ///
    /// - Parameter message: The event.
    /// - Returns: It, stamped.
    private func stamped(_ message: Message) -> Message {
        var message = message
        message.stampAncestorKeys(from: lineage)
        return message
    }

    /// - Parameter message: An event.
    /// - Returns: The ancestor keys its exec or fork carries.
    private func keys(_ message: Message) -> [String]? {
        switch message.event {
        case .exec(let exec): exec.ancestor_keys
        case .fork(let fork): fork.ancestor_keys
        default: nil
        }
    }

    /// A fork names the forking process first, then its ancestors, whether or not the table has heard of the fork.
    /// An exec has the same ancestors as the process had before it, whether the table has heard of neither the fork
    /// nor the exec, of the fork alone, or of both.
    func testAnExecAndAForkAreStamped() throws {
        let fork = try forkMessage(by: try parentShell(), of: try child(2))
        let exec = try execMessage(by: try child(2), of: try child(3))
        XCTAssertNil(keys(fork))
        XCTAssertEqual(keys(stamped(fork)), ["100.1", "50.1"])
        XCTAssertEqual(keys(stamped(exec)), ["100.1", "50.1"], "The table has heard of neither")

        lineage.fork(ProcessKey(pid: 200, pidversion: 2), from: ProcessKey(pid: 100, pidversion: 1))
        XCTAssertEqual(keys(stamped(fork)), ["100.1", "50.1"])
        XCTAssertEqual(keys(stamped(exec)), ["100.1", "50.1"], "The table has heard of the fork")

        lineage.exec(ProcessProgram(key: ProcessKey(pid: 200, pidversion: 3), path: "/usr/bin/true"),
                     replacing: ProcessKey(pid: 200, pidversion: 2), at: 0)
        XCTAssertEqual(keys(stamped(exec)), ["100.1", "50.1"], "The table has heard of both")

        let grandchild = try esloggerProcess(pid: 300, pidversion: 4, path: "/usr/bin/true", parent: (200, 3))
        XCTAssertEqual(keys(stamped(try forkMessage(by: try child(3), of: grandchild))), ["200.3", "100.1", "50.1"])
    }

    /// A child of launchd has no ancestors, which is an empty list and not a missing one. An event that creates no
    /// process is left alone.
    func testAChildOfLaunchdAndOtherEvents() throws {
        let job = try esloggerProcess(pid: 400, pidversion: 8, path: "/usr/libexec/xpcproxy", parent: (1, 7))
        let target = try esloggerProcess(pid: 400, pidversion: 9, path: "/usr/libexec/agent", parent: (1, 7))
        XCTAssertEqual(keys(stamped(try execMessage(by: job, of: target))), [])
        let exit = stamped(try exitMessage(of: try child(3)))
        XCTAssertNil(keys(exit))
    }

    /// A capture lane tells the table of the forks, execs and exits it builds, with the values their records have,
    /// so the table is never behind the lane: a shell the table never heard of, its child and its child's exec are
    /// all stamped from the lane's own events.
    func testALaneTellsTheTableOfItsEvents() throws {
        let table = ProcessLineage()
        let daemon = try esloggerProcess(pid: 60, pidversion: 1, path: "/usr/sbin/sshd", parent: (1, 7))
        let forked = try esloggerProcess(pid: 70, pidversion: 2, path: "/usr/sbin/sshd", parent: (60, 1))
        let session = try esloggerProcess(pid: 70, pidversion: 3, path: "/bin/zsh", parent: (60, 1))
        let events = [try forkMessage(by: daemon, of: forked), try execMessage(by: forked, of: session),
                      try forkMessage(by: session, of: try esloggerProcess(pid: 80, pidversion: 4, path: "/bin/zsh",
                                                                           parent: (70, 3)))]
        var stamped: [[String]?] = []
        for var event in events {
            table.note(event, at: 0)
            event.stampAncestorKeys(from: table)
            stamped.append(keys(event))
        }
        XCTAssertEqual(stamped, [["60.1"], ["60.1"], ["70.3", "60.1"]])
        let shell = try XCTUnwrap(table.program(ProcessKey(pid: 70, pidversion: 3)))
        guard case .exec(let exec) = events[1].event else { return XCTFail("Not an exec") }
        XCTAssertEqual(shell, ProcessProgram(key: ProcessKey(pid: 70, pidversion: 3), path: "/bin/zsh",
                                             commandLine: exec.command_line, signingID: exec.target.signing_id,
                                             teamID: exec.target.team_id,
                                             codesigningType: exec.target.codesigning_type.rawValue))
        XCTAssertNotNil(shell.commandLine)

        table.note(try exitMessage(of: session), at: 0)
        XCTAssertNotNil(table.program(ProcessKey(pid: 70, pidversion: 3)), "It lingers")
        table.note(try exitMessage(of: daemon), at: ProcessLineage.lingers)
        XCTAssertNil(table.program(ProcessKey(pid: 70, pidversion: 3)))
    }

    /// A lane tells the table who really caused a process to run, from the launched-by parent its exec or fork
    /// carries: a process by its token, one known only by its pid, and none when it's the Unix parent.
    func testALaneTellsTheTableWhoLaunchedAProcess() throws {
        let table = ProcessLineage()
        table.seed([(ProcessProgram(key: ProcessKey(pid: 100, pidversion: 1), path: "/Applications/Host.app"), 1),
                    (ProcessProgram(key: ProcessKey(pid: 110, pidversion: 5), path: "/Applications/Other.app"), 1)])
        let proxy = try esloggerProcess(pid: 200, pidversion: 1, path: "/usr/libexec/xpcproxy", parent: (1, 7))
        let service = try esloggerProcess(pid: 200, pidversion: 2, path: "/Helper.xpc", parent: (1, 7))
        var exec = try execMessage(by: proxy, of: service)
        let launched = { (key: ProcessKey) in table.ancestors(of: key, chain: .launchedBy).map(\.path) }
        exec.setLaunchedByParent(LaunchedByParent(source: .responsibleProcess,
                                                  audit_token: .fixture(pid: 100, pidversion: 1),
                                                  path: "/Applications/Host.app", resolved_by: .securityExtension))
        table.note(exec, at: 0)
        XCTAssertEqual(launched(ProcessKey(pid: 200, pidversion: 2)), ["/Applications/Host.app"])
        XCTAssertEqual(table.ancestors(of: ProcessKey(pid: 200, pidversion: 2)), [])

        exec.setLaunchedByParent(LaunchedByParent(source: .launchServices, audit_token: nil, pid: 110, path: nil,
                                                  resolved_by: .securityExtension))
        table.note(exec, at: 0)
        XCTAssertEqual(launched(ProcessKey(pid: 200, pidversion: 2)), ["/Applications/Other.app"])

        XCTAssertNil(ProcessLineage.launcher(nil))
        XCTAssertNil(ProcessLineage.launcher(LaunchedByParent(source: .unixParent,
                                                              audit_token: .fixture(pid: 100, pidversion: 1),
                                                              path: nil, resolved_by: .securityExtension)))
        XCTAssertNil(ProcessLineage.launcher(LaunchedByParent(source: .launchServices, audit_token: nil, path: nil,
                                                              resolved_by: .securityExtension)))
    }

    /// The keys survive the wire from the Security Extension, with either encoder, and an event without them still
    /// reads.
    func testTheKeysSurviveTheWire() throws {
        for message in [stamped(try execMessage(by: try child(2), of: try child(3))),
                        stamped(try forkMessage(by: try parentShell(), of: try child(2))),
                        try execMessage(by: try child(2), of: try child(3))] {
            for data in [try StreamingJSONEncoder().encode(message), try JSONEncoder().encode(message)] {
                XCTAssertEqual(keys(try JSONDecoder().decode(Message.self, from: data)), keys(message))
            }
        }
    }

    /// An exported record always has the key: the list, or `null` when the event carries none. File > Open Trace
    /// reads the list back.
    func testTheKeysAreExportedAndReadBack() throws {
        let encoder = ExportEncoder(model: try XCTUnwrap(ExportEncoder.model))
        for (name, message) in [("exec", try execMessage(by: try child(2), of: try child(3))),
                                ("fork", try forkMessage(by: try parentShell(), of: try child(2)))] {
            let bare = try XCTUnwrap(try JSONSerialization.jsonObject(with: encoder.line(for: message))
                                     as? [String: Any])
            XCTAssertTrue(bare[path: "event", .key(name), "ancestor_keys"] is NSNull, name)

            let line = encoder.line(for: stamped(message))
            let record = try XCTUnwrap(try JSONSerialization.jsonObject(with: line) as? [String: Any])
            XCTAssertEqual(record[path: "event", .key(name), "ancestor_keys"] as? [String], ["100.1", "50.1"], name)
            XCTAssertEqual(keys(try importRecord(record)), ["100.1", "50.1"], name)
        }
    }

    /// A fork message for the shell's child.
    ///
    /// - Returns: The message.
    private func rawFork() -> RawMessageFixture {
        let message = rawMessage(type: ES_EVENT_TYPE_NOTIFY_FORK)
        message.fork(childPID: 200, parent: RawMessageFixture.auditToken(pid: 100),
                     responsible: RawMessageFixture.auditToken(pid: 100))
        return message
    }

    /// The serializer stamps a fork from its lane's lineage table, telling the table of the fork first, and stamps
    /// none for a lane without a table: an empty one would say every process is a child of launchd.
    func testTheSerializerStampsFromItsLanesTable() throws {
        let serializer = MessageSerializer()
        let message = rawFork()
        let fork = { (table: ProcessLineage?) throws -> [String]? in
            let lane = LaneContext(eventClass: .process, sensorID: "SENSOR", encoder: StreamingJSONEncoder(),
                                   lineage: table)
            guard case .json(let data)? = serializer.serializeEvent(message.message, in: lane) else {
                XCTFail("Not encoded")
                return nil
            }
            return self.keys(try JSONDecoder().decode(Message.self, from: data))
        }
        XCTAssertNil(try fork(nil))
        XCTAssertEqual(try fork(lineage), ["100.1", "50.1"])
        XCTAssertNotNil(lineage.program(ProcessKey(pid: 200, pidversion: 1)), "The lane told the table of the fork")
    }

    /// A session's lanes take no event until the processes that were already running are in the table. An event
    /// of one of them handled sooner would find its ancestors by their keys alone, and a rule on them would miss.
    func testACaptureSessionWaitsForTheRunningProcesses() throws {
        let sshd = ProcessProgram(key: ProcessKey(pid: 50, pidversion: 1), path: "/usr/sbin/sshd")
        let monitor = LineageMonitor(lineage: ProcessLineage(), factory: FakeEndpointSecurityClientFactory(),
                                     running: { usleep(20_000); return [(sshd, 1, nil)] })
        let factory = FakeEndpointSecurityClientFactory()
        var wasSeeded: [Bool] = []
        factory.onSubscribe = { _, _ in wasSeeded.append(monitor.lineage.program(sshd.key) != nil) }
        let configuration = CaptureConfiguration(events: [ES_EVENT_TYPE_NOTIFY_EXEC], label: "Test")
        let session = try CaptureSession(configuration, clients: factory, serializer: MessageSerializer(),
                                         sensorID: { "SENSOR" }, lineage: monitor, emit: { _ in })
        XCTAssertFalse(wasSeeded.isEmpty)
        XCTAssertTrue(wasSeeded.allSatisfy { $0 }, "\(wasSeeded)")
        XCTAssertTrue(monitor.waitUntilSeeded(timeout: .never))
        session.stop()
    }

    /// A capture session keeps the lineage monitor running from before its first subscription until it stops, and
    /// its lanes stamp from the monitor's table. One that can't start lets the monitor go. One whose monitor
    /// Endpoint Security refuses a client captures all the same, and stamps nothing.
    func testACaptureSessionKeepsLineageRunning() throws {
        let monitor = LineageMonitor(lineage: lineage, factory: FakeEndpointSecurityClientFactory(), running: { [] })
        let factory = FakeEndpointSecurityClientFactory()
        var wasRunning: [Bool] = []
        factory.onSubscribe = { _, _ in wasRunning.append(monitor.isRunning) }
        let emitted = EmittedEvents()
        let configuration = CaptureConfiguration(events: [ES_EVENT_TYPE_NOTIFY_FORK], label: "Test")
        let session = try CaptureSession(configuration, clients: factory, serializer: MessageSerializer(),
                                         sensorID: { "SENSOR" }, lineage: monitor, emit: emitted.append)
        XCTAssertFalse(wasRunning.isEmpty)
        XCTAssertTrue(wasRunning.allSatisfy { $0 })
        XCTAssertTrue(monitor.isRunning)
        session.isRecording = true
        factory.client(.process).deliver(rawFork())
        let events = emitted.all.map(\.json).filter { !ProcessSnapshotRecord.isSnapshot($0) }
        XCTAssertEqual(try events.map { keys(try JSONDecoder().decode(Message.self, from: $0)) },
                       [["100.1", "50.1"]])
        session.stop()
        XCTAssertFalse(monitor.isRunning)
        session.stop()
        XCTAssertFalse(monitor.isRunning)

        let deaf = FakeEndpointSecurityClientFactory(refusing: [0: [.subscribe]])
        XCTAssertThrowsError(try CaptureSession(configuration, clients: deaf, serializer: MessageSerializer(),
                                                sensorID: { "SENSOR" }, lineage: monitor, emit: { _ in }))
        XCTAssertFalse(monitor.isRunning)
        let none = FakeEndpointSecurityClientFactory(refusals: [0: .tooManyClients])
        XCTAssertThrowsError(try CaptureSession(configuration, clients: none, serializer: MessageSerializer(),
                                                sensorID: { "SENSOR" }, lineage: monitor, emit: { _ in }))
        XCTAssertFalse(monitor.isRunning)

        let refused = LineageMonitor(lineage: ProcessLineage(),
                                     factory: FakeEndpointSecurityClientFactory(refusals: [0: .tooManyClients]),
                                     running: { [] })
        let unstamped = EmittedEvents()
        let other = FakeEndpointSecurityClientFactory()
        let untracked = try CaptureSession(configuration, clients: other, serializer: MessageSerializer(),
                                           sensorID: { "SENSOR" }, lineage: refused, emit: unstamped.append)
        untracked.isRecording = true
        other.client(.process).deliver(rawFork())
        XCTAssertEqual(try unstamped.all.map { keys(try JSONDecoder().decode(Message.self, from: $0.json)) },
                       [nil])
        untracked.stop()
    }
}
