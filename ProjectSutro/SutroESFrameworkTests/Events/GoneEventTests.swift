//
//  GoneEventTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/25/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - Events that are gone
/// Pins what happens to an event a view is still showing when a Clear deletes it. Its rows go first, so until the view
/// context hears, its relationships read nil: on macOS 13 an exec label forced its nil exec and Mac Monitor crashed.
/// A Clear must tell the view context about every event it loaded, and no view may force an event's payload it hasn't
/// checked for. A Clear usually replaces the store, after which the view context forgets everything; while an export
/// reads the store it deletes the rows instead, and must name every event the view context loaded.
final class GoneEventTests: XCTestCase {
    /// An event the view context loads after a Clear begins, as a table can in the turn before it lets go, is gone
    /// once a Clear that replaces the store finishes.
    func testClearDeletesWhatLoadedDuringIt() throws {
        try assertClearForgetsWhatLoadedDuringIt(whileExporting: false)
    }
    
    /// The same for a Clear that deletes the rows, while an export reads the store: not left alive with its rows deleted.
    func testClearDuringAnExportDeletesWhatLoadedDuringIt() throws {
        try assertClearForgetsWhatLoadedDuringIt(whileExporting: true)
    }
    
    /// Load an exec before a Clear and one during it, then check both are gone once it finishes.
    ///
    /// - Parameter whileExporting: Whether an export is reading the store, so the Clear deletes rather than replaces.
    /// - Throws: The error reading the corpus.
    private func assertClearForgetsWhatLoadedDuringIt(whileExporting: Bool) throws {
        let store = CoreDataController(model: eventModel)
        let exporter = TelemetryExporter(container: store.container, pretty: false)
        if whileExporting {
            let url = try makeTemporaryDirectory().appendingPathComponent("trace.jsonl")
            store.exports.withLock { $0[ObjectIdentifier(exporter)] = (exporter, url) }
        }
        defer { store.exports.withLock { $0[ObjectIdentifier(exporter)] = nil } }
        let stores = { store.container.persistentStoreCoordinator.persistentStores.map(\.identifier) }
        let viewContext = store.container.viewContext
        /// As the event tables leave it (`EventQueryModel.activate(spec:)`).
        viewContext.automaticallyMergesChangesFromParent = false
        let inserted = expectation(description: "inserted")
        store.insertSystemEvents(messages: try SyntheticCorpus.records().map(\.message)) { inserted.fulfill() }
        wait(for: [inserted], timeout: 60)

        let request = NSFetchRequest<NSManagedObjectID>(entityName: "ESMessage")
        request.resultType = .managedObjectIDResultType
        request.predicate = NSPredicate(format: "event_type == %d", ESMessage.execEventType)
        let execs = try viewContext.fetch(request)
        let early = try XCTUnwrap(execs.first.flatMap { try? viewContext.existingObject(with: $0) as? ESMessage })
        XCTAssertNotNil(early.event.exec)
        let before = stores()

        let cleared = expectation(forNotification: CoreDataController.eventsDidClear, object: store)
        store.clearSystemEvents()
        /// Loaded after the Clear began and before its delete, which waits a turn of the run loop.
        let late = try XCTUnwrap(execs.dropFirst().first.flatMap {
            try? viewContext.existingObject(with: $0) as? ESMessage
        })
        XCTAssertNotNil(late.event.exec)
        wait(for: [cleared], timeout: 60)
        XCTAssertEqual(stores() == before, whileExporting, whileExporting ? "Replaced the store from under an export"
                       : "Deleted the rows rather than replacing the store")
        
        for (name, message) in [("loaded before", early), ("loaded during", late)] {
            XCTAssertTrue(message.isDeleted || message.managedObjectContext == nil,
                          "An exec \(name) the Clear is still alive, its exec \(String(describing: message.event.exec))")
        }
    }

    /// No view in the app forces an event's type, and a view forces an event's payload only in the property its body
    /// checks for first: `if message.event.exec != nil`, as the label views do.
    func testNoViewForcesWhatItHasNotChecked() throws {
        let app = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("ProjectSutro")
        let forced = try NSRegularExpression(pattern: #"(\w+)\.event\.(\w+)!|\.es_event_type!"#)
        let property = try NSRegularExpression(pattern: #"var \w+: [\w.]+ \{\s*\w+\.event\.\w+!\s*\}"#)
        var offenders: [String] = [], scanned = 0
        let files = try XCTUnwrap(FileManager.default.enumerator(at: app, includingPropertiesForKeys: nil))
        for case let file as URL in files where file.pathExtension == "swift" {
            let source = try String(contentsOf: file, encoding: .utf8)
            scanned += 1
            let range = NSRange(source.startIndex..., in: source)
            let properties = property.matches(in: source, range: range).map(\.range)
            for match in forced.matches(in: source, range: range) {
                let text = String(source[Range(match.range, in: source)!])
                let line = source[..<Range(match.range, in: source)!.lowerBound].filter { $0 == "\n" }.count + 1
                let checked = match.range(at: 1).location != NSNotFound
                    && properties.contains { NSIntersectionRange($0, match.range).length > 0 }
                    && source.contains("\(source[Range(match.range(at: 1), in: source)!]).event."
                                       + "\(source[Range(match.range(at: 2), in: source)!]) != nil")
                if !checked { offenders.append("\(file.lastPathComponent):\(line): \(text)") }
            }
        }
        /// The app's sources are beside the tests: a run without them reads none and finds nothing.
        XCTAssertGreaterThan(scanned, 100, "Read \(scanned) Swift files under \(app.path)")
        XCTAssertEqual(offenders, [], "Read an event's payload with ?. or check it in body before forcing it")
    }
}
