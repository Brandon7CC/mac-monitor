//
//  XCTestCase+Export.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import CoreData
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Exports without the event store
/// The event model, loaded once: Core Data complains when a second copy of a model claims the same classes.
let eventModel = NSManagedObjectModel(
    contentsOf: Bundle(for: ESMessage.self).url(forResource: "SystemEvents", withExtension: "momd")!)!


extension XCTestCase {
    /// Read an event as the app keeps it: an `ESMessage`, in a context with no store, so nothing is saved.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - body: Reads the stored event, on its context's queue.
    /// - Returns: What `body` returns.
    /// - Throws: What `body` throws.
    func withStoredEvent<T>(_ message: Message, _ body: (ESMessage) throws -> T) rethrows -> T {
        let context = NSManagedObjectContext(concurrencyType: .privateQueueConcurrencyType)
        context.persistentStoreCoordinator = NSPersistentStoreCoordinator(managedObjectModel: eventModel)
        return try context.performAndWait {
            defer { context.reset() }
            return try body(ESMessage(from: message, insertIntoManagedObjectContext: context))
        }
    }
    
    /// An event's export as the exporter writes it: the stored event (``withStoredEvent(_:_:)``) encoded with
    /// `ProcessHelpers.eventToJSON(value:)`.
    ///
    /// - Parameter message: The event.
    /// - Returns: The export's JSON text, for checks on exact digits.
    func exportText(_ message: Message) -> String {
        withStoredEvent(message) { ProcessHelpers.eventToJSON(value: $0) }
    }
    
    /// An event's export, parsed.
    ///
    /// - Parameter message: The event.
    /// - Returns: The export's JSON object.
    /// - Throws: An `XCTest` failure if the export isn't a JSON object.
    func export(_ message: Message) throws -> [String: Any] {
        try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(exportText(message).utf8)) as? [String: Any])
    }
    
    /// One event's object in an export: `event.<name>`.
    ///
    /// - Parameters:
    ///   - name: The event's key, such as `gatekeeper_user_override`.
    ///   - export: The export.
    /// - Returns: The event's object.
    /// - Throws: An `XCTest` failure if the export has no such event.
    func event(_ name: String, in export: [String: Any]) throws -> [String: Any] {
        try XCTUnwrap((export["event"] as? [String: Any])?[name] as? [String: Any], "No event \(name) in \(export)")
    }
    
    /// An eslogger record: the synthetic eslogger exit event with another event in its place.
    ///
    /// - Parameters:
    ///   - name: The event's key, such as `gatekeeper_user_override`.
    ///   - type: The event's `event_type`.
    ///   - event: The event's object.
    ///   - version: The message's version.
    /// - Returns: The record.
    /// - Throws: The error reading the exit fixture.
    func esloggerRecord(_ name: String, type: Int, _ event: [String: Any], version: Int = 10) throws -> [String: Any] {
        var record = try fixtureObject("eslogger-exit.jsonl")
        record["event"] = [name: event]
        record["event_type"] = type
        record["version"] = version
        return record
    }
    
    /// A Mac Monitor 2.1 export: the 2.1 exit fixture with another event in its place.
    ///
    /// - Parameters:
    ///   - name: The event's key, such as `mprotect`.
    ///   - type: The event's type.
    ///   - event: The event's object, as Mac Monitor 2.1 exported it.
    /// - Returns: The record.
    /// - Throws: The error reading the exit fixture.
    func legacyRecord(_ name: String, type: es_event_type_t, _ event: Any) throws -> [String: Any] {
        var record = try fixtureObject("macmonitor-2.1-exit.jsonl")
        record["event"] = [name: event]
        record["event_type"] = Int(type.rawValue)
        record["es_event_type"] = eventTypeToString(from: type)
        return record
    }
    
    /// A record read as File > Open Trace… reads it.
    ///
    /// - Parameter record: The record, as JSON text.
    /// - Returns: The event.
    /// - Throws: The error ``TraceImporter/message(from:)`` throws.
    func importRecord(_ record: String) throws -> Message {
        try TraceImporter.message(from: Data(record.utf8))
    }
    
    /// A record read as File > Open Trace… reads it.
    ///
    /// - Parameter record: The record's object.
    /// - Returns: The event.
    /// - Throws: The error serializing the record, or the error ``TraceImporter/message(from:)`` throws.
    func importRecord(_ record: [String: Any]) throws -> Message {
        try TraceImporter.message(from: try JSONSerialization.data(withJSONObject: record))
    }
}
