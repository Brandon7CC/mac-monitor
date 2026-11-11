//
//  ProcessAgeExportTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - Process ages in the store and the export
/// Pins how process ages are stored and exported: a shared process row (an initiating process, an exec's target, a
/// fork's child) holds no age and each event keeps its own, an owned row holds its own, and every process object an
/// export writes has `process_age_ms`, `null` when it's unknown.
final class ProcessAgeExportTests: XCTestCase {
    /// Store events as the app does, with row caches, so equal processes share one row, and read them back.
    ///
    /// - Parameters:
    ///   - messages: The events, in order.
    ///   - body: Reads the store, given its context and the stored events, in order.
    /// - Returns: What `body` returns.
    /// - Throws: The error adding the store or saving, or what `body` throws.
    private func withSharedRows<T>(_ messages: [Message],
                                   _ body: (NSManagedObjectContext, [ESMessage]) throws -> T) throws -> T {
        let coordinator = NSPersistentStoreCoordinator(managedObjectModel: eventModel)
        try coordinator.addPersistentStore(ofType: NSInMemoryStoreType, configurationName: nil, at: nil)
        let context = NSManagedObjectContext(concurrencyType: .privateQueueConcurrencyType)
        context.persistentStoreCoordinator = coordinator
        return try context.performAndWait {
            context.userInfo[EventRowCaches.userInfoKey] = EventRowCaches()
            let stored = messages.enumerated().map { order, message in
                ESMessage(storing: message, order: Int64(order), batch: 1, in: context)
            }
            try context.save()
            return try body(context, stored)
        }
    }

    /// The ages of a store's process rows.
    ///
    /// - Parameter context: The store's context.
    /// - Returns: Each row's own age, `nil` for none.
    /// - Throws: The error fetching the rows.
    private func rowAges(in context: NSManagedObjectContext) throws -> [Int?] {
        try context.fetch(NSFetchRequest<ESProcess>(entityName: "ESProcess")).map { $0.process_age_ms?.intValue }
    }

    /// A value at a path of a stored event's export.
    ///
    /// - Parameters:
    ///   - stored: The stored event.
    ///   - path: The path into its export.
    /// - Returns: The value there.
    /// - Throws: An `XCTest` failure if the export isn't a JSON object.
    private func exported(_ stored: ESMessage, _ path: JSONStep...) throws -> Any? {
        try jsonObject(Data(ProcessHelpers.eventToJSON(value: stored).utf8))[path: path]
    }

    /// The same message again, as a later event of the same processes, with other ages.
    ///
    /// - Parameters:
    ///   - message: The first event.
    ///   - age: The later event's initiating process's age.
    ///   - eventAge: The later event's other processes' age.
    /// - Returns: The later event.
    private func later(_ message: Message, age: Int, eventAge: Int) -> Message {
        var later = message
        later.id = UUID()
        later.process.process_age_ms = age
        later.event.forEachProcess { $0.process_age_ms = eventAge }
        return later
    }

    // MARK: Shared rows

    /// Two exits of one process share one row, and each exports its own age.
    func testInitiatingProcessKeepsEachEventsAge() throws {
        let first = try exitMessage(of: try shell())
        let second = later(first, age: 200_000, eventAge: 0)
        XCTAssertEqual(first.process.process_age_ms, 114_281)
        try withSharedRows([first, second]) { context, stored in
            XCTAssertEqual(try rowAges(in: context), [nil], "One shared row, without an age")
            XCTAssertEqual(stored.map(\.process_age_ms), [114_281, 200_000])
            XCTAssertEqual(stored.map(\.processAge), [114.281, 200])
            XCTAssertEqual(try exported(stored[0], "process", "process_age_ms") as? Int, 114_281)
            XCTAssertEqual(try exported(stored[1], "process", "process_age_ms") as? Int, 200_000)
            /// The search reads each event's own age, not the shared row's.
            let young = try StreamFilter.Predicate("process.process_age_ms < 150000", for: .search)
            XCTAssertEqual(try stored.map { try young.evaluate(on: $0) }, [true, false])
        }
    }

    /// Two execs of one image share its rows, and each exports its own target's age.
    func testExecTargetKeepsEachEventsAge() throws {
        let login = try esloggerProcess(pid: 401, pidversion: 4009, path: "/usr/bin/login", parent: (300, 3000))
        let first = try execMessage(by: login, of: try shell())
        let second = later(first, age: 1, eventAge: 2)
        try withSharedRows([first, second]) { context, stored in
            XCTAssertEqual(try rowAges(in: context), [nil, nil], "The exec'ing image and the target, shared")
            XCTAssertEqual(stored.map { $0.event.exec?.target_age_ms?.intValue }, [114_281, 2])
            XCTAssertEqual(try exported(stored[0], "event", "exec", "target", "process_age_ms") as? Int, 114_281)
            XCTAssertEqual(try exported(stored[1], "event", "exec", "target", "process_age_ms") as? Int, 2)
            XCTAssertEqual(try exported(stored[1], "process", "process_age_ms") as? Int, 1)
        }
    }

    /// Two forks of one child share its row, and each exports its own child's age.
    func testForkChildKeepsEachEventsAge() throws {
        let child = try esloggerProcess(pid: 402, pidversion: 4020, path: "/bin/zsh", parent: (401, 4010))
        let first = try forkMessage(by: try shell(), of: child)
        let second = later(first, age: 1, eventAge: 2)
        try withSharedRows([first, second]) { context, stored in
            XCTAssertEqual(try rowAges(in: context), [nil, nil])
            XCTAssertEqual(stored.map { $0.event.fork?.childAge }, [114.281, 0.002])
            XCTAssertEqual(try exported(stored[0], "event", "fork", "child", "process_age_ms") as? Int, 114_281)
            XCTAssertEqual(try exported(stored[1], "event", "fork", "child", "process_age_ms") as? Int, 2)
        }
    }

    // MARK: Owned rows

    /// A signal's instigator and target have rows of their own, which hold their ages.
    func testOwnedRowsHoldTheirAge() throws {
        var signal = try XCTUnwrap(try SyntheticCorpus.records().first { $0.label == "signal (full)" }).message
        signal.process.process_age_ms = 1
        var next = 2
        signal.event.forEachProcess { $0.process_age_ms = next; next += 1 }
        try withSharedRows([signal]) { context, stored in
            XCTAssertEqual(try rowAges(in: context).compactMap { $0 }.sorted(), [2, 3])
            XCTAssertEqual(try exported(stored[0], "process", "process_age_ms") as? Int, 1)
            XCTAssertEqual(try exported(stored[0], "event", "signal", "instigator", "process_age_ms") as? Int, 2)
            XCTAssertEqual(try exported(stored[0], "event", "signal", "target", "process_age_ms") as? Int, 3)
        }
    }

    // MARK: The export

    /// Every process object of every synthetic event's export has the key: its age, or `null` when it has none.
    func testEveryProcessIsExportedWithItsAge() throws {
        /// Every process object in a JSON value: the objects with `codesigning_flag_names`, which only processes have.
        func processObjects(in value: Any) -> [[String: Any]] {
            if let object = value as? [String: Any] {
                let own = object["codesigning_flag_names"] == nil ? [] : [object]
                return own + object.values.flatMap(processObjects)
            }
            return (value as? [Any])?.flatMap(processObjects) ?? []
        }
        for record in try SyntheticCorpus.records() {
            var event = record.message.event, expected = [record.message.process.process_age_ms]
            event.forEachProcess { expected.append($0.process_age_ms) }
            let objects = processObjects(in: try export(record.message))
            XCTAssertEqual(objects.count, expected.count, record.label)
            XCTAssertTrue(objects.allSatisfy { $0.keys.contains("process_age_ms") }, record.label)
            let ages = objects.map { $0["process_age_ms"] as? Int }
            XCTAssertEqual(ages.map { $0 ?? .min }.sorted(), expected.map { $0 ?? .min }.sorted(), record.label)
            if !record.variant.full {
                XCTAssertTrue(objects.allSatisfy { $0["process_age_ms"] is NSNull }, record.label)
            }
        }
    }

    /// An export of a fresh store follows the bundled schema, telemetry 1.1.0, and every event's ages come back from
    /// disk: the initiating process's, the exec's target's and the fork's child's.
    func testFreshExportFollowsTheSchema() throws {
        let login = try esloggerProcess(pid: 401, pidversion: 4009, path: "/usr/bin/login", parent: (300, 3000))
        var child = try esloggerProcess(pid: 402, pidversion: 4020, path: "/bin/zsh", parent: (401, 4010))
        /// 5 s before the fork, at 2026-10-04T00:01:55.281215406Z.
        child["start_time"] = "2026-10-04T00:01:50.281215Z"
        let messages = [try execMessage(by: login, of: try shell()), try forkMessage(by: try shell(), of: child),
                        try exitMessage(of: try shell())]
        let (url, events) = try exportAll(try makeExportStore(messages))
        XCTAssertEqual(events, 3)
        let validator = try TelemetryValidator(schema: try TelemetrySchema.data())
        XCTAssertEqual(validator.schemaVersion, "1.1.0")
        let lines = try String(contentsOf: url, encoding: .utf8).split(separator: "\n").map(String.init)
        assertValid(lines.enumerated().map { (label: "line \($0 + 1)", json: $1) }, with: validator)
        let records = try lines.map { try jsonObject(Data($0.utf8)) }
        for record in records {
            XCTAssertEqual(record[TelemetrySchema.versionKey] as? String, "1.1.0")
            XCTAssertEqual(record[path: "process", "process_age_ms"] as? Int, 114_281)
        }
        let exec = try XCTUnwrap(records.first { $0[path: "event", "exec"] != nil })
        XCTAssertEqual(exec[path: "event", "exec", "target", "process_age_ms"] as? Int, 114_281)
        let fork = try XCTUnwrap(records.first { $0[path: "event", "fork"] != nil })
        XCTAssertEqual(fork[path: "event", "fork", "child", "process_age_ms"] as? Int, 5_000)
    }
}
