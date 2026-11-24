//
//  StoredSnapshotsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Snapshots in the app's exports
/// Pins what Mac Monitor does with process snapshots: an export writes each before the first record that names its
/// process, a selection's export makes one from the exec it leaves out, File > Open Trace keeps a trace's and
/// exports them again as they were, and a Clear keeps a recording's.
final class StoredSnapshotsTests: XCTestCase {
    /// A store holding the capture with snapshots, as Mac Monitor would after receiving it.
    ///
    /// - Returns: The store, and its events in order.
    /// - Throws: If a fixture can't be read.
    private func recording() throws -> (store: CoreDataController, events: [Message]) {
        let store = CoreDataController(model: eventModel)
        let lines = try captureWithSnapshots()
        lines.compactMap(ProcessSnapshotRecord.read).forEach(store.recordedSnapshots.add)
        var events = try lines.filter { !ProcessSnapshotRecord.isSnapshot($0) }
            .map { try JSONDecoder().decode(Message.self, from: $0) }
        /// A recording exports by time.
        for index in events.indices { events[index].mach_time = Int64(index + 1) }
        let saved = expectation(description: "saved")
        store.insertSystemEvents(messages: events) { saved.fulfill() }
        wait(for: [saved], timeout: 60)
        return (store, events)
    }

    /// Export a store's events as JSONL.
    ///
    /// - Parameters:
    ///   - selection: The events to export, or `nil` for all of them.
    ///   - store: The store.
    /// - Returns: The file's bytes, and how many events the export counted.
    /// - Throws: The export's error.
    private func export(_ selection: [UUID]? = nil, of store: CoreDataController) throws -> (file: Data, events: Int) {
        let url = try makeTemporaryDirectory().appendingPathComponent("trace.jsonl")
        let exported = expectation(description: "exported")
        var result: Result<Int, Error>?
        store.exportEvents(selection, to: url, jsonl: true) { result = $0; exported.fulfill() }
        wait(for: [exported], timeout: 60)
        return (try Data(contentsOf: url), try XCTUnwrap(result).get())
    }

    /// What each line of an export is: a snapshot's key, or an event's type.
    ///
    /// - Parameter file: An export.
    /// - Returns: Each line's kind, in order.
    private func kinds(_ file: Data) -> [String] {
        file.split(separator: 0x0A).map { line in
            let object = (try? JSONSerialization.jsonObject(with: Data(line))) as? [String: Any] ?? [:]
            if let key = object[path: "process_snapshot", "key"] as? String { return key }
            return (object["es_event_type"] as? String)?.replacingOccurrences(of: "ES_EVENT_TYPE_NOTIFY_", with: "")
                ?? "?"
        }
    }

    /// The whole trace: the Security Extension's snapshots come before the fork that first names their processes,
    /// each once, the export counts events only, and the file still ends without a newline.
    func testAnExportWritesSnapshotsBeforeTheRecordThatNamesThem() throws {
        let (store, _) = try recording()
        let (file, events) = try export(of: store)
        XCTAssertEqual(kinds(file), ["50.1", "100.1", "FORK", "EXEC", "FORK", "EXEC"])
        XCTAssertEqual(events, 4)
        XCTAssertNotEqual(file.last, 0x0A)
        let sent = try captureWithSnapshots().filter(ProcessSnapshotRecord.isSnapshot)
        XCTAssertEqual(file.split(separator: 0x0A).prefix(2).map { Data($0) }, sent, "As they were sent")
    }

    /// A selection of the last exec alone: its ancestors are the two snapshots and its parent, whose exec the
    /// selection leaves out and the export makes a snapshot from.
    func testASelectionsExportDescribesTheAncestorsItLeavesOut() throws {
        let (store, events) = try recording()
        let (file, count) = try export([events[3].id], of: store)
        XCTAssertEqual(kinds(file), ["50.1", "100.1", "200.3", "EXEC"])
        XCTAssertEqual(count, 1)
        let made = try XCTUnwrap(ProcessSnapshotRecord.read(Data(file.split(separator: 0x0A)[2])))
        XCTAssertEqual(made.process_snapshot.executable?.path, "/bin/sh")
        XCTAssertEqual(made.process_snapshot.ancestor_keys, ["100.1", "50.1"])
    }

    /// File > Open Trace keeps a trace's snapshots, and exporting the opened trace writes them again. Opening
    /// another trace, or a Clear, lets them go. A recording's outlast a Clear.
    func testAnOpenedTraceKeepsItsSnapshots() throws {
        let (store, _) = try recording()
        let (file, _) = try export(of: store)
        let url = try temporaryFile(containing: String(decoding: file, as: UTF8.self), named: "exported.jsonl")
        let other = CoreDataController(model: eventModel)
        let summary = try openTrace(url, in: other)
        XCTAssertEqual(summary.saved, 4)
        XCTAssertEqual(summary.skipped, 0)
        XCTAssertEqual(Set(other.snapshots.current.keys.map(\.description)), ["50.1", "100.1"])
        XCTAssertTrue(other.recordedSnapshots.current.isEmpty)
        /// The events gain what opening a trace derives, such as launched-by parents. The snapshots don't change.
        let reexported = try export(of: other).file
        XCTAssertEqual(kinds(reexported), kinds(file))
        XCTAssertEqual(reexported.split(separator: 0x0A).prefix(2), file.split(separator: 0x0A).prefix(2))

        /// Each trace has its own: one still being read when the next opens adds nothing to the next's.
        let opened = other.traceSnapshots
        clear(other)
        XCTAssertTrue(other.traceSnapshots.current.isEmpty)
        XCTAssertFalse(opened === other.traceSnapshots)
        XCTAssertFalse(opened.current.isEmpty)

        clear(store)
        XCTAssertEqual(store.snapshots.current.keys.count, 2, "The capture won't describe them again")
    }

    /// A Clear deletes the execs that described the processes still running. Mac Monitor keeps each exec's and
    /// fork's process as a snapshot as it receives them, so an event after the Clear that names them is still
    /// exported with all of its ancestors.
    func testAnExportAfterAClearStillDescribesTheAncestors() throws {
        let (store, events) = try recording()
        events.forEach(store.recordedSnapshots.add(creatorOf:))
        clear(store)
        var later = events[3]
        later.id = UUID()
        later.mach_time = 9
        /// A Clear discards what happened before it.
        later.message_darwin_time = Date().addingTimeInterval(60)
        let saved = expectation(description: "saved")
        store.insertSystemEvents(messages: [later]) { saved.fulfill() }
        wait(for: [saved], timeout: 60)
        XCTAssertEqual(kinds(try export(of: store).file), ["50.1", "100.1", "200.3", "EXEC"])
    }

    /// However many snapshots a long recording keeps, the ones the Security Extension sent reach the export.
    func testALongRecordingsSnapshotsReachTheExport() throws {
        let (store, _) = try recording()
        for pid in Int32(1_000)..<21_000 {
            let program = ProcessProgram(key: ProcessKey(pid: pid, pidversion: 1), path: "/usr/libexec/xpcproxy")
            store.recordedSnapshots.add(ProcessSnapshotRecord(ProcessSnapshot(program, ancestors: []), sensorID: nil))
        }
        XCTAssertEqual(kinds(try export(of: store).file), ["50.1", "100.1", "FORK", "EXEC", "FORK", "EXEC"])
    }

    /// Clear a store's events, and wait until they're gone.
    ///
    /// - Parameter store: The store.
    private func clear(_ store: CoreDataController) {
        let cleared = expectation(forNotification: CoreDataController.eventsDidClear, object: store)
        store.clearSystemEvents()
        wait(for: [cleared], timeout: 60)
    }
}
