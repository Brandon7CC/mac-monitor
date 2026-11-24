//
//  ProcessSnapshotTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Process snapshots
/// Pins the snapshot a trace holds of a process it has no exec of: its line, which ancestors a capture owes one
/// for and in what order, that each is written once, and that a table rebuilt from a trace's forks, execs and
/// snapshots answers as the Security Extension's did.
final class ProcessSnapshotTests: XCTestCase {
    private let daemon = ProcessKey(pid: 50, pidversion: 1)
    private let shell = ProcessKey(pid: 100, pidversion: 1)
    private var lineage = ProcessLineage()

    /// A table that knows sshd and the shell it started, as a capture that began after both would.
    override func setUp() {
        super.setUp()
        lineage = ProcessLineage()
        lineage.seed([(ProcessProgram(key: daemon, path: "/usr/sbin/sshd", commandLine: "sshd: quintus",
                                      signingID: "com.apple.sshd", codesigningType: "PLATFORM"), 1),
                      (ProcessProgram(key: shell, path: "/bin/zsh", commandLine: "-zsh"), 50)])
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

    /// The shell forking its child, and the child's exec, stamped from the test's table as a lane would.
    ///
    /// - Returns: The fork and the exec, each with the ancestors it was stamped with.
    /// - Throws: If a fixture can't be read.
    private func forkAndExec() throws -> [(event: Message, ancestors: [ProcessProgram]?)] {
        let shell = try esloggerProcess(pid: 100, pidversion: 1, path: "/bin/zsh", parent: (50, 1))
        return try [forkMessage(by: shell, of: try child(2)), execMessage(by: try child(2), of: try child(3))]
            .map { message in
                var message = message
                lineage.note(message, at: 0)
                let ancestors = message.stampAncestorKeys(from: lineage)
                return (message, ancestors)
            }
    }

    /// A process and its ancestors, nearest first, as a lane hands them to the ledger.
    ///
    /// - Parameter key: The process.
    /// - Returns: The chain.
    /// - Throws: A failure when the table doesn't know the process.
    private func chain(of key: ProcessKey) throws -> [ProcessProgram] {
        [try XCTUnwrap(lineage.program(key))] + lineage.ancestors(of: key)
    }

    /// A snapshot's line starts with its own key, which is how it's told from an event's without decoding either,
    /// and reads back as it was written. It carries a process's fields under a process's names.
    func testASnapshotsLine() throws {
        let program = try XCTUnwrap(lineage.program(daemon))
        let record = ProcessSnapshotRecord(ProcessSnapshot(program, ancestors: []), sensorID: "SENSOR")
        let line = try XCTUnwrap(record.line)
        XCTAssertTrue(ProcessSnapshotRecord.isSnapshot(line))
        XCTAssertEqual(ProcessSnapshotRecord.read(line), record)
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: line) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["process_snapshot", "sensor_id"])
        let snapshot = try XCTUnwrap(object["process_snapshot"] as? [String: Any])
        XCTAssertEqual(snapshot["key"] as? String, "50.1")
        XCTAssertEqual(snapshot["ancestor_keys"] as? [String], [])
        XCTAssertEqual(snapshot[path: "executable", "path"] as? String, "/usr/sbin/sshd")
        XCTAssertEqual(snapshot["command_line"] as? String, "sshd: quintus")
        XCTAssertEqual(snapshot["signing_id"] as? String, "com.apple.sshd")
        XCTAssertEqual(snapshot["codesigning_type"] as? String, "PLATFORM")
        XCTAssertNil(snapshot["team_id"], "A field with no value is left out")
        XCTAssertEqual(record.process_snapshot.program, program)

        /// With the boot session the records beside it carry, its own key still comes first.
        let booted = ProcessSnapshotRecord(record.process_snapshot, sensorID: "SENSOR",
                                           bootSession: "0F1E2D3C-4B5A-4978-8695-A4B3C2D1E0F9")
        let later = try XCTUnwrap(booted.line)
        XCTAssertTrue(ProcessSnapshotRecord.isSnapshot(later))
        XCTAssertTrue(String(decoding: later, as: UTF8.self)
            .hasSuffix(#","boot_session_uuid":"0F1E2D3C-4B5A-4978-8695-A4B3C2D1E0F9","sensor_id":"SENSOR"}"#))
        XCTAssertEqual(ProcessSnapshotRecord.read(later), booted)

        let event = try StreamingJSONEncoder().encode(try forkAndExec()[1].event)
        XCTAssertFalse(ProcessSnapshotRecord.isSnapshot(event))
        XCTAssertNil(ProcessSnapshotRecord.read(event))
    }

    /// The telemetry schema describes a snapshot's line in its own definition, and the validator checks one against
    /// it: a line as Mac Monitor writes it is valid, with every field or only the two it always has, and one whose
    /// key isn't a process key, or with a key the definition doesn't have, is not.
    func testASnapshotsLineFollowsTheSchema() throws {
        let validator = try TelemetryValidator.bundled()
        let program = ProcessProgram(key: daemon, path: "/usr/sbin/sshd", commandLine: "sshd",
                                     signingID: "com.apple.sshd", teamID: "TEAM", codesigningType: "PLATFORM")
        let full = ProcessSnapshotRecord(ProcessSnapshot(program, ancestors: [shell]), sensorID: "SENSOR")
        let bare = ProcessSnapshotRecord(ProcessSnapshot(ProcessProgram(key: daemon), ancestors: []), sensorID: "S")
        /// A test fixture's snapshot has no Sensor ID.
        let scrubbed = ProcessSnapshotRecord(full.process_snapshot, sensorID: nil)
        for record in [full, bare, scrubbed] {
            XCTAssertEqual(validator.issues(inRecord: try XCTUnwrap(record.line)).map(\.description), [])
        }
        XCTAssertEqual(ProcessSnapshotRecord.read(try XCTUnwrap(scrubbed.line)), scrubbed)
        var object = try XCTUnwrap(try JSONSerialization.jsonObject(with: try XCTUnwrap(full.line)) as? [String: Any])
        object[path: "process_snapshot", "key"] = "sshd"
        XCTAssertEqual(validator.issues(in: object).count, 1)
        object[path: "process_snapshot", "key"] = "50.1"
        object["es_event_type"] = "ES_EVENT_TYPE_NOTIFY_EXEC"
        XCTAssertEqual(validator.issues(in: object).count, 1, "A snapshot's line has no event's keys")
    }

    /// A chain owes a snapshot for each of its processes that nothing has described, farthest first, once, each
    /// naming the rest of the chain. One a record describes owes none, nor does launchd.
    func testTheLedgerDescribesEachProcessOnce() throws {
        let ledger = SnapshotLedger()
        let due = ledger.due(for: try chain(of: shell))
        XCTAssertEqual(due.map(\.key), ["50.1", "100.1"], "The shell's parent first")
        XCTAssertEqual(due.map(\.ancestor_keys), [[], ["50.1"]])
        XCTAssertEqual(ledger.due(for: try chain(of: shell)), [])
        XCTAssertTrue(ledger.isDescribed(daemon))

        let other = SnapshotLedger()
        other.recorded(shell)
        XCTAssertEqual(other.due(for: try chain(of: shell)).map(\.key), ["50.1"])
        XCTAssertEqual(other.due(for: [ProcessProgram(key: ProcessKey(pid: 1, pidversion: 7), path: "/sbin/launchd")]),
                       [])
    }

    /// A process the table knows only by its key owes nothing yet and isn't counted as described, so it's
    /// described once the table has read it: a capture can name a parent before the running processes are read.
    func testAProcessKnownByItsKeyAloneIsDescribedLater() throws {
        let ledger = SnapshotLedger()
        let unread = ProcessKey(pid: 700, pidversion: 9)
        XCTAssertEqual(ledger.due(for: [ProcessProgram(key: unread)]), [])
        XCTAssertFalse(ledger.isDescribed(unread))
        XCTAssertEqual(ledger.due(for: [ProcessProgram(key: unread, path: "/bin/zsh")]).map(\.key), ["700.9"])
    }

    /// An ancestor the table has forgotten by its key, because it exited long ago, is still described: its
    /// children carry its program, and the snapshot is made from that.
    func testAnAncestorThatExitedIsStillDescribed() throws {
        lineage.exit(daemon, at: 0)
        lineage.exit(ProcessKey(pid: 999, pidversion: 1), at: ProcessLineage.lingers)
        XCTAssertNil(lineage.program(daemon), "Forgotten by its key")
        let due = SnapshotLedger().due(for: try chain(of: shell))
        XCTAssertEqual(due.map(\.key), ["50.1", "100.1"])
        XCTAssertEqual(due[0].executable?.path, "/usr/sbin/sshd")
    }

    /// A lane owes the snapshots of the ancestors its fork names before the fork, and nothing more for the exec
    /// that follows: the fork described the child, and the ancestors were described already.
    func testALaneOwesSnapshotsBeforeTheFirstRecordThatNamesThem() throws {
        let snapshots = LaneSnapshots(ledger: SnapshotLedger())
        let events = try forkAndExec()
        snapshots.describe(events[0].event, naming: events[0].ancestors, from: lineage)
        let lines = snapshots.take()
        XCTAssertEqual(lines.compactMap { ProcessSnapshotRecord.read($0)?.process_snapshot.key }, ["50.1", "100.1"])
        XCTAssertEqual(lines.compactMap { ProcessSnapshotRecord.read($0)?.sensor_id }.first, events[0].event.sensor_id)
        XCTAssertEqual(snapshots.take(), [])
        snapshots.describe(events[1].event, naming: events[1].ancestors, from: lineage)
        XCTAssertEqual(snapshots.take(), [])

        let grandchild = try esloggerProcess(pid: 300, pidversion: 4, path: "/usr/bin/true", parent: (200, 3))
        var fork = try forkMessage(by: try child(3), of: grandchild)
        lineage.note(fork, at: 0)
        let ancestors = fork.stampAncestorKeys(from: lineage)
        snapshots.describe(fork, naming: ancestors, from: lineage)
        XCTAssertEqual(snapshots.take(), [], "Its parent has an exec in the trace")
    }

    /// An event that creates no process owes a snapshot of its own process and that process's ancestors, the
    /// first time the lane sees the process: one that was running before the capture has no exec in the trace. A
    /// process a record described owes none. One the table hasn't been told of yet, as a process whose exec
    /// another lane is still to hand over, is described as the event itself says it, under its parent's ancestors.
    func testAnEventOwesItsOwnProcesssSnapshot() throws {
        let snapshots = LaneSnapshots(ledger: SnapshotLedger())
        let keys = { snapshots.take().compactMap { ProcessSnapshotRecord.read($0)?.process_snapshot.key } }
        let shell = try exitMessage(of: try esloggerProcess(pid: 100, pidversion: 1, path: "/bin/zsh",
                                                            parent: (50, 1)))
        snapshots.describe(shell, naming: nil, from: lineage)
        XCTAssertEqual(keys(), ["50.1", "100.1"])
        snapshots.describe(shell, naming: nil, from: lineage)
        XCTAssertEqual(keys(), [], "Once")

        let events = try forkAndExec()
        events.forEach { snapshots.describe($0.event, naming: $0.ancestors, from: lineage) }
        snapshots.describe(try exitMessage(of: try child(3)), naming: nil, from: lineage)
        XCTAssertEqual(keys(), [], "Its exec is in the trace")

        let stranger = try exitMessage(of: try esloggerProcess(pid: 800, pidversion: 5, path: "/bin/ls",
                                                               parent: (100, 1)))
        snapshots.describe(stranger, naming: nil, from: lineage)
        let described = snapshots.take().compactMap { ProcessSnapshotRecord.read($0)?.process_snapshot }
        XCTAssertEqual(described.map(\.key), ["800.5"], "As the event says it, under ancestors described already")
        XCTAssertEqual(described.first?.executable?.path, "/bin/ls")
        XCTAssertEqual(described.first?.ancestor_keys, ["100.1", "50.1"])
        XCTAssertNil(described.first?.command_line, "Only its exec has that")
        snapshots.describe(stranger, naming: nil, from: lineage)
        XCTAssertEqual(keys(), [], "Once")

        let orphan = try exitMessage(of: try esloggerProcess(pid: 900, pidversion: 7, path: "/bin/cat",
                                                             parent: (850, 6)))
        snapshots.describe(orphan, naming: nil, from: lineage)
        XCTAssertEqual(keys(), ["900.7"], "With no ancestors known, it's still said what it is")
    }

    /// A process whose tree the table wasn't told of is looked up as an indicator's lookup would: its parents are
    /// read from the system, so its snapshot names the ancestors the capture evaluated it with.
    func testAnEventsSnapshotReadsParentsTheTableWasNotToldOf() throws {
        let node = ProcessProgram(key: ProcessKey(pid: 700, pidversion: 3), path: "/usr/local/bin/node",
                                  commandLine: "node npm install")
        lineage = ProcessLineage { $0 == 700 ? (node, 100) : nil }
        lineage.seed([(ProcessProgram(key: shell, path: "/bin/zsh", commandLine: "-zsh"), 1)])
        let snapshots = LaneSnapshots(ledger: SnapshotLedger())
        let writer = try exitMessage(of: try esloggerProcess(pid: 800, pidversion: 5, path: "/bin/bash",
                                                             parent: (700, 3)))
        snapshots.describe(writer, naming: nil, from: lineage)
        let described = snapshots.take().compactMap { ProcessSnapshotRecord.read($0)?.process_snapshot }
        XCTAssertEqual(described.map(\.key), ["100.1", "700.3", "800.5"])
        XCTAssertEqual(described.last?.ancestor_keys, ["700.3", "100.1"])
        XCTAssertEqual(described.dropLast().last?.command_line, "node npm install")
    }

    /// The table keeps at most 1,024 characters of a command line, cut on a character, and a shorter one whole.
    func testACommandLineIsCapped() {
        let long = String(repeating: "é", count: 3_000)
        let program = ProcessProgram(key: shell, path: "/bin/zsh", commandLine: long)
        XCTAssertEqual(program.commandLine, String(repeating: "é", count: ProcessProgram.commandLineLimit))
        XCTAssertEqual(ProcessProgram(key: shell, commandLine: "-zsh").commandLine, "-zsh")
        XCTAssertNil(ProcessProgram(key: shell).commandLine)
    }

    /// A trace's table finds a process by its own key only. The Security Extension's also tries the newest program
    /// of the pid, which in a trace read whole can be another process that reused the pid much later.
    func testATracesTableFindsAProcessByItsOwnKeyOnly() throws {
        let events = try forkAndExec().map(\.event)
        let live = ProcessLineage(), replay = ProcessLineage.replaying()
        for table in [live, replay] { events.forEach { table.note($0, at: 0) } }
        let earlier = ProcessKey(pid: 200, pidversion: 1)
        XCTAssertEqual(live.ancestors(of: earlier).map(\.key.description), ["100.1"])
        XCTAssertEqual(replay.ancestors(of: earlier), [])
        XCTAssertEqual(replay.ancestors(of: ProcessKey(pid: 200, pidversion: 3)).map(\.key.description), ["100.1"])
    }

    /// A capture session emits the snapshots ahead of the event that names them, each once for the session.
    func testACaptureSessionEmitsSnapshotsAheadOfTheEvent() throws {
        let monitor = LineageMonitor(lineage: lineage, factory: FakeEndpointSecurityClientFactory(), running: { [] })
        let factory = FakeEndpointSecurityClientFactory()
        let emitted = EmittedEvents()
        let session = try CaptureSession(CaptureConfiguration(events: [ES_EVENT_TYPE_NOTIFY_FORK], label: "Test"),
                                         clients: factory, serializer: MessageSerializer(), sensorID: { "SENSOR" },
                                         lineage: monitor, emit: emitted.append)
        session.isRecording = true
        for _ in 0..<2 {
            let message = rawMessage(type: ES_EVENT_TYPE_NOTIFY_FORK)
            message.fork(childPID: 200, parent: RawMessageFixture.auditToken(pid: 100),
                         responsible: RawMessageFixture.auditToken(pid: 100))
            factory.client(.process).deliver(message)
        }
        session.stop()
        let kinds = emitted.all.map { ProcessSnapshotRecord.read($0.json)?.process_snapshot.key ?? "event" }
        XCTAssertEqual(kinds, ["50.1", "100.1", "event", "event"])
        XCTAssertEqual(ProcessSnapshotRecord.read(emitted.all[0].json)?.sensor_id, "SENSOR")
    }

    /// A table told only what a trace holds answers as the Security Extension's did: the snapshots in any order,
    /// then the fork and the exec. A snapshot never replaces what an event said of a process.
    func testATableIsRebuiltFromATrace() throws {
        let events = try forkAndExec().map(\.event)
        let snapshots = SnapshotLedger().due(for: try chain(of: shell))
        let rebuilt = ProcessLineage()
        for snapshot in snapshots.reversed() {
            rebuilt.describe(try XCTUnwrap(snapshot.program), ancestors: snapshot.ancestors)
        }
        events.forEach { rebuilt.note($0, at: 0) }
        for key in [ProcessKey(pid: 200, pidversion: 2), ProcessKey(pid: 200, pidversion: 3), shell, daemon] {
            XCTAssertEqual(rebuilt.ancestors(of: key), lineage.ancestors(of: key), key.description)
            XCTAssertEqual(rebuilt.program(key), lineage.program(key), key.description)
        }
        XCTAssertEqual(rebuilt.ancestors(of: ProcessKey(pid: 200, pidversion: 3)).map(\.path),
                       ["/bin/zsh", "/usr/sbin/sshd"])

        rebuilt.describe(ProcessProgram(key: ProcessKey(pid: 200, pidversion: 3), path: "/elsewhere"),
                         ancestors: [daemon])
        XCTAssertEqual(rebuilt.program(ProcessKey(pid: 200, pidversion: 3))?.path, "/usr/bin/true")
        XCTAssertEqual(rebuilt.ancestors(of: ProcessKey(pid: 200, pidversion: 3)).map(\.key), [shell, daemon])
        rebuilt.describe(ProcessProgram(key: ProcessKey(pid: 1, pidversion: 7), path: "/sbin/launchd"), ancestors: [])
        XCTAssertNil(rebuilt.program(ProcessKey(pid: 1, pidversion: 7)), "launchd is never listed")
    }
}
