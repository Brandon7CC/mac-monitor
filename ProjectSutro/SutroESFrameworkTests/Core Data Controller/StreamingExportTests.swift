//
//  StreamingExportTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/25/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - Streaming exports
/// Pins the export's fast path to what it replaced: where ``StreamingJSONEncoder`` sorts keys as this Mac's
/// `JSONEncoder` does, every stored event's record is byte for byte ``ProcessHelpers/eventToJSON(value:)``'s, and an
/// export fetched and encoded by several workers at once is byte for byte the events, in file order, through
/// `eventToJSON`.
final class StreamingExportTests: XCTestCase {
    /// Keys out of order at every level, an object inside an array, an empty object, and strings with slashes.
    private struct Unsorted: Encodable {
        struct Inner: Encodable {
            enum CodingKeys: String, CodingKey { case path_truncated, path, z, a1, a_b }
            func encode(to encoder: Encoder) throws {
                var container = encoder.container(keyedBy: CodingKeys.self)
                try container.encode(true, forKey: .path_truncated)
                try container.encode("/usr/bin/true", forKey: .path)
                try container.encodeNil(forKey: .z)
                try container.encode(1.5, forKey: .a1)
                try container.encode([String](), forKey: .a_b)
            }
        }
        struct Empty: Encodable {}
        let zeta = 1
        let inner = Inner()
        let list = [Inner(), Inner()]
        let empty = Empty()
        let alpha = "a/b\\c\"d\n"
    }

    /// A key written twice, which `JSONEncoder` writes once, with the last value.
    private struct Twice: Encodable {
        enum CodingKeys: String, CodingKey { case b, a }
        func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(1, forKey: .b)
            try container.encode(2, forKey: .a)
            try container.encode(3, forKey: .b)
        }
    }

    /// `JSONEncoder` as exports use it.
    private var sortedEncoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    /// Sorted keys at every depth, slashes left alone, and a key twice left to `JSONEncoder`.
    func testSortsKeysAsJSONEncoderDoes() throws {
        try XCTSkipUnless(StreamingJSONEncoder.sortsKeysAsJSONEncoderDoes,
                          "JSONEncoder here sorts as NSString compares")
        let encoder = StreamingJSONEncoder(sortsKeys: true, escapesSlashes: false)
        for (name, value) in [("unsorted", Unsorted() as Encodable), ("twice", Twice())] {
            XCTAssertEqual(String(decoding: try encoder.encode(value), as: UTF8.self),
                           String(decoding: try sortedEncoder.encode(value), as: UTF8.self), name)
        }
        /// The capture lanes' encoder is unchanged: members in encode order, slashes escaped.
        XCTAssertEqual(String(decoding: try StreamingJSONEncoder().encode(Unsorted.Inner()), as: UTF8.self),
                       #"{"path_truncated":true,"path":"\/usr\/bin\/true","z":null,"a1":1.5,"a_b":[]}"#)
    }

    /// Every event type's synthetic records (every field filled, and every optional left out) and every fixture's
    /// events, stored, encode byte for byte as `eventToJSON` encodes them.
    func testEveryEventEncodesAsEventToJSON() throws {
        try XCTSkipUnless(StreamingJSONEncoder.sortsKeysAsJSONEncoderDoes,
                          "JSONEncoder here sorts as NSString compares")
        let encoder = StreamingJSONEncoder(sortsKeys: true, escapesSlashes: false)
        let events = try SyntheticCorpus.records().map { ($0.label, $0.message) }
            + allFixtureMessages().enumerated().map { ("fixture[\($0)]", $1) }
        var different: [String] = []
        for (label, message) in events {
            withStoredEvent(message) { stored in
                let streamed = String(decoding: (try? encoder.encode(stored)) ?? Data("{}".utf8), as: UTF8.self)
                if streamed != ProcessHelpers.eventToJSON(value: stored) { different.append(label) }
            }
        }
        XCTAssertGreaterThan(events.count, TelemetrySchemaSource.events.count * 2)
        XCTAssertEqual(different, [], "Encoded differently from eventToJSON")
    }

    /// Every event, in file order, through `eventToJSON`, joined by newlines: what an export writes.
    ///
    /// - Parameter container: The store.
    /// - Returns: The file's text.
    /// - Throws: The error fetching the events.
    private func expectedExport(of container: NSPersistentContainer) throws -> String {
        let context = container.newBackgroundContext()
        return try context.performAndWait {
            let request = NSFetchRequest<ESMessage>(entityName: "ESMessage")
            request.sortDescriptors = [NSSortDescriptor(key: "mach_time", ascending: true),
                                       NSSortDescriptor(key: "insert_order", ascending: true)]
            return try context.fetch(request).map { ProcessHelpers.eventToJSON(value: $0) }.joined(separator: "\n")
        }
    }

    /// Export every event of a store.
    ///
    /// - Parameters:
    ///   - exporter: The export, pinned or not.
    ///   - url: The destination.
    /// - Returns: The number of events written.
    /// - Throws: The export's error.
    private func run(_ exporter: TelemetryExporter, to url: URL) throws -> Int {
        let exported = expectation(description: "exported")
        var result: Result<Int, Error>?
        exporter.run(to: url, writeIfEmpty: true, choose: { try $0.allEvents(through: 1, from: .live) }) {
            result = $0
            exported.fulfill()
        }
        wait(for: [exported], timeout: 120)
        return try XCTUnwrap(result).get()
    }

    /// Every worker reads the store as it was when the export was pinned, through every batch it encodes: deleting
    /// every row afterwards changes nothing in the file.
    func testWorkersKeepTheSnapshotThroughADelete() throws {
        let corpus = try SyntheticCorpus.records().map(\.message)
        let count = TelemetryExporter.batchSize * 10 + 77
        let container = try makeExportStore((0..<count).map { order in
            var message = corpus[order % corpus.count]
            message.id = UUID()
            message.mach_time = Int64(order)
            return message
        })
        let expected = try expectedExport(of: container)
        let exporter = TelemetryExporter(container: container, pretty: false, workers: 4)
        exporter.pin()

        let deleter = container.newBackgroundContext()
        try deleter.performAndWait {
            for entity in container.managedObjectModel.entities where entity.superentity == nil {
                try deleter.execute(NSBatchDeleteRequest(fetchRequest: NSFetchRequest(entityName: entity.name!)))
                XCTAssertEqual(try deleter.count(for: NSFetchRequest(entityName: entity.name!)), 0)
            }
        }

        let url = try makeTemporaryDirectory().appendingPathComponent("trace.jsonl")
        XCTAssertEqual(try run(exporter, to: url), count)
        XCTAssertTrue(String(decoding: try Data(contentsOf: url), as: UTF8.self) == expected,
                      "A worker read past the snapshot")
    }

    /// A store in memory, as Mac Monitor keeps its events when their file can't be kept (SQLite at /dev/null), can't be
    /// pinned: the export runs unpinned rather than raising an exception Swift can't catch.
    func testStoreInMemoryExportsUnpinned() throws {
        let container = NSPersistentContainer(name: "SystemEvents", managedObjectModel: eventModel)
        container.persistentStoreDescriptions = [NSPersistentStoreDescription(url: URL(fileURLWithPath: "/dev/null"))]
        var loadError: Error?
        container.loadPersistentStores { _, error in loadError = error }
        if let loadError { throw loadError }
        let messages = try SyntheticCorpus.records().map(\.message)
        let context = container.newBackgroundContext()
        try context.performAndWait {
            for (order, message) in messages.enumerated() {
                let stored = ESMessage(from: message, insertIntoManagedObjectContext: context)
                stored.insert_order = Int64(order)
                stored.insert_batch = 1
                stored.denormalize(from: message)
            }
            try context.save()
        }
        let exporter = TelemetryExporter(container: container, pretty: false)
        exporter.pin()
        let url = try makeTemporaryDirectory().appendingPathComponent("trace.jsonl")
        XCTAssertEqual(try run(exporter, to: url), messages.count)
        XCTAssertTrue(String(decoding: try Data(contentsOf: url), as: UTF8.self) == (try expectedExport(of: container)))
    }

    /// Four workers write the file one worker writes, and both are every event in file order through `eventToJSON`,
    /// joined by newlines: over more rounds than one, with a short last round.
    func testWorkersWriteTheFileInOrder() throws {
        let corpus = try SyntheticCorpus.records().map(\.message)
        let count = TelemetryExporter.batchSize * 9 + 123
        let container = try makeExportStore((0..<count).map { order in
            var message = corpus[order % corpus.count]
            message.id = UUID()
            message.mach_time = Int64(count - order)
            return message
        })
        let expected = try container.viewContext.performAndWait {
            let request = NSFetchRequest<ESMessage>(entityName: "ESMessage")
            request.sortDescriptors = [NSSortDescriptor(key: "mach_time", ascending: true)]
            return try container.viewContext.fetch(request).map { ProcessHelpers.eventToJSON(value: $0) }
                .joined(separator: "\n")
        }
        for workers in [1, 4] {
            let url = try makeTemporaryDirectory().appendingPathComponent("trace.jsonl")
            let exported = expectation(description: "exported by \(workers)")
            var result: Result<Int, Error>?
            TelemetryExporter(container: container, pretty: false, workers: workers).run(to: url, writeIfEmpty: true,
                                                                                         choose: {
                try $0.allEvents(through: 1, from: .live)
            }) {
                result = $0
                exported.fulfill()
            }
            wait(for: [exported], timeout: 120)
            XCTAssertEqual(try XCTUnwrap(result).get(), count, "\(workers) workers")
            XCTAssertTrue(String(decoding: try Data(contentsOf: url), as: UTF8.self) == expected,
                          "\(workers) workers wrote a different file")
        }
    }
}
