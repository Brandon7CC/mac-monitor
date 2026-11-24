//
//  StreamSnapshotsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - A stream's snapshots
/// Pins the process snapshots `macmonitor stream` writes among its records: the Security Extension's, before the
/// first record written that names their process, each once. A stream that leaves out the exec an ancestor had
/// writes that ancestor as a snapshot. Text writes none, and one nothing names is never written.
final class StreamSnapshotsTests: XCTestCase {
    private let nobody = PipelineScope(ancestry: [PipelineAncestor(pid: .max, groupID: 0, path: "/x/macmonitor")],
                                       includeSelf: false)

    /// What each line of output is: a snapshot's key, or an event's type.
    ///
    /// - Parameter output: A pipeline's JSONL output.
    /// - Returns: Each line's kind, in order.
    private func kinds(_ output: Data) -> [String] {
        output.split(separator: 0x0A).map { line in
            let object = (try? JSONSerialization.jsonObject(with: Data(line))) as? [String: Any] ?? [:]
            if let key = object[path: "process_snapshot", "key"] as? String { return key }
            return (object["es_event_type"] as? String)?.replacingOccurrences(of: "ES_EVENT_TYPE_NOTIFY_", with: "")
                ?? "?"
        }
    }

    /// - Parameters:
    ///   - filter: Which events are written.
    ///   - limit: The most events to write.
    /// - Returns: A pipeline that writes JSONL.
    private func pipeline(_ filter: StreamFilter = StreamFilter(), limit: Int? = nil) -> StreamPipeline {
        StreamPipeline(formatter: .jsonl([ExportEncoder(model: eventModel)]), scope: nobody, forTerminal: false,
                       filter: filter, limit: limit)
    }

    /// With nothing left out, the Security Extension's snapshots are written where it sent them, as it sent them,
    /// and the records are the export's. They aren't events: they're neither counted nor unreadable.
    func testSnapshotsAreWrittenBeforeTheRecordThatNamesThem() throws {
        let lines = try captureWithSnapshots()
        XCTAssertEqual(lines.filter(ProcessSnapshotRecord.isSnapshot).count, 2)
        let stream = pipeline()
        let output = stream.process(lines)
        XCTAssertEqual(kinds(output), ["50.1", "100.1", "FORK", "EXEC", "FORK", "EXEC"])
        XCTAssertEqual(stream.written, 4)
        XCTAssertEqual(stream.unreadable, 0)
        let written = output.split(separator: 0x0A).map { Data($0) }
        XCTAssertEqual(Array(written.prefix(2)), Array(lines.prefix(2)), "Byte for byte")
        XCTAssertEqual(kinds(stream.process(Array(lines.suffix(2)))), ["FORK", "EXEC"], "Nothing is owed twice")
    }

    /// A stream of one process's events leaves out the execs its ancestors had. The first record written is
    /// preceded by every ancestor it names, farthest first: the two the Security Extension described, and the one
    /// whose exec was left out, made from that exec.
    func testAnAncestorWhoseExecWasLeftOutIsWrittenAsASnapshot() throws {
        var filter = StreamFilter()
        filter.pids = [300]
        let stream = pipeline(filter)
        let output = stream.process(try captureWithSnapshots())
        XCTAssertEqual(kinds(output), ["50.1", "100.1", "200.3", "EXEC"])
        XCTAssertEqual(stream.written, 1)
        XCTAssertEqual(stream.filtered, 3)
        let made = try XCTUnwrap(ProcessSnapshotRecord.read(Data(output.split(separator: 0x0A)[2])))
        XCTAssertEqual(made.process_snapshot.executable?.path, "/bin/sh")
        XCTAssertEqual(made.process_snapshot.ancestor_keys, ["100.1", "50.1"])
        XCTAssertNotNil(made.process_snapshot.command_line)
    }

    /// A record that creates no process needs its own process described. A stream of exits alone leaves out every
    /// exec and fork, and its one record is preceded by its process and that process's ancestors, each made from
    /// the exec that was left out or sent by the Security Extension.
    func testARecordsOwnProcessIsDescribed() throws {
        var filter = StreamFilter()
        filter.predicates = [try StreamFilter.Predicate("event.exit != nil")]
        let stream = pipeline(filter)
        let output = stream.process(try captureWithSnapshots(exits: true))
        XCTAssertEqual(kinds(output), ["50.1", "100.1", "200.3", "300.5", "EXIT"])
        XCTAssertEqual(stream.written, 1)
        let own = try XCTUnwrap(ProcessSnapshotRecord.read(Data(output.split(separator: 0x0A)[3])))
        XCTAssertEqual(own.process_snapshot.executable?.path, "/usr/bin/true")
        XCTAssertEqual(own.process_snapshot.ancestor_keys, ["200.3", "100.1", "50.1"])
        XCTAssertEqual(kinds(pipeline().process(try captureWithSnapshots(exits: true))).suffix(2), ["EXEC", "EXIT"],
                       "With its exec written, the exit owes nothing")
    }

    /// A snapshot can come after the record that needs it, as a held app's exec comes after its children's
    /// events. It's written as soon as it comes, once, ahead of whatever is written next.
    func testASnapshotThatComesLateIsStillWritten() throws {
        let lines = try captureWithSnapshots()
        let stream = pipeline()
        XCTAssertEqual(kinds(stream.process([lines[2]])), ["FORK"], "Its ancestors aren't known yet")
        XCTAssertEqual(kinds(stream.process([lines[1], lines[0], lines[3]])), ["50.1", "100.1", "EXEC"])
        XCTAssertEqual(kinds(stream.process(Array(lines.suffix(2)))), ["FORK", "EXEC"])
    }

    /// The table drops the oldest snapshots made from execs and forks past its limit, and never one that was
    /// sent: those are the only description of their processes. A sent one is preferred to a made one.
    func testTheTableDropsTheOldestMadeSnapshots() {
        let record = { (pid: Int32, path: String) in
            ProcessSnapshotRecord(ProcessSnapshot(ProcessProgram(key: ProcessKey(pid: pid, pidversion: 1), path: path),
                                                  ancestors: []), sensorID: nil)
        }
        var table = SnapshotTable(limit: SnapshotTable.Limit(count: 2))
        table.keep(record(9, "/sent"), made: false)
        for pid in Int32(1)...4 { table.keep(record(pid, "/made"), made: true) }
        XCTAssertEqual(table.keys, Set([9, 3, 4].map { ProcessKey(pid: $0, pidversion: 1) }))
        table.keep(record(4, "/sent-too"), made: false)
        XCTAssertEqual(table.take(ProcessKey(pid: 4, pidversion: 1))?.process_snapshot.executable?.path, "/sent-too")
        XCTAssertEqual(table.take(ProcessKey(pid: 4, pidversion: 1))?.process_snapshot.executable?.path, "/made")
        XCTAssertNil(table.take(ProcessKey(pid: 4, pidversion: 1)))

        var small = SnapshotTable(limit: SnapshotTable.Limit(count: 100, bytes: 600))
        for pid in Int32(1)...3 { small.keep(record(pid, "/made"), made: true) }
        XCTAssertEqual(small.keys.count, 2, "By their size too")
        var all = SnapshotTable(limit: nil)
        for pid in Int32(1)...50 { all.keep(record(pid, "/made"), made: true) }
        XCTAssertEqual(all.keys.count, 50)
    }

    /// A snapshot nothing written names is never written, a limit counts events only, and text has no snapshots.
    func testSnapshotsFollowWhatIsWritten() throws {
        var filter = StreamFilter()
        filter.pids = [9_999]
        XCTAssertEqual(pipeline(filter).process(try captureWithSnapshots()), Data())
        XCTAssertEqual(kinds(pipeline(limit: 1).process(try captureWithSnapshots())), ["50.1", "100.1", "FORK"])

        let utc = TextEventFormatter(timeZone: TimeZone(identifier: "UTC")!)
        let text = StreamPipeline(formatter: .text(utc), scope: nobody, forTerminal: true)
        let output = String(decoding: text.process(try captureWithSnapshots()), as: UTF8.self)
        XCTAssertEqual(output.split(separator: "\n").count, 4)
        XCTAssertFalse(output.contains("process_snapshot"))
        XCTAssertEqual(text.unreadable, 0)
    }
}
