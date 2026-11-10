//
//  IOKitServiceExportTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - An IOKit open's service in the store, the export, the wire and traces
/// Pins `parent_class` and `driver_bundle_id` from capture to export: the event store keeps them, the export always
/// writes both keys (`null` when unknown) and follows the schema, the wire carries them, a 3.0.0 Security Extension's
/// message and a trace without them decode with none, opening a trace never reads this Mac's registry, and the
/// Non-Apple driver opened indicator matches on them.
final class IOKitServiceExportTests: XCTestCase {
    /// An IOKit open of IOSurfaceRoot, captured as the Security Extension captures it.
    ///
    /// - Returns: The event.
    /// - Throws: `XCTSkip` when this Mac's registry doesn't have IOSurfaceRoot.
    private func captured() throws -> Message {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN)
        fixture.message.pointee.event.iokit_open.user_client_class = fixture.token("IOSurfaceRootUserClient")
        fixture.message.pointee.event.iokit_open.parent_path = fixture.token(IOKitRegistryServiceTests.surfaceRoot)
        let message = Message(from: fixture.raw)
        guard message.event.iokit_open?.parent_class != nil else { throw XCTSkip("No IOSurfaceRoot on this Mac") }
        return message
    }

    /// - Parameters:
    ///   - message: An IOKit open.
    ///   - driver: The driver bundle ID to give it.
    /// - Returns: The open, with that driver.
    private func opening(_ message: Message, driver: String?) -> Message {
        var changed = message
        guard case .iokit_open(var event) = message.event else { return message }
        event.driver_bundle_id = driver
        changed.event = .iokit_open(event)
        return changed
    }

    /// An IOKit open as eslogger writes it, naming IOSurfaceRoot, which is in this Mac's registry.
    ///
    /// - Parameter version: The message's version. Before 10 it has no parent.
    /// - Returns: The record.
    /// - Throws: The error reading the fixture.
    private func esloggerOpen(version: Int = 10) throws -> [String: Any] {
        var event: [String: Any] = ["user_client_class": "IOSurfaceRootUserClient", "user_client_type": 0]
        if version >= 10 {
            event["parent_path"] = IOKitRegistryServiceTests.surfaceRoot
            event["parent_registry_id"] = 4_294_967_895
        }
        return try esloggerRecord(ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, event, version: version)
    }

    // MARK: Export

    /// A captured open exports its service's class and an Apple driver's bundle ID.
    func testCapturedServiceExports() throws {
        let event = try event("iokit_open", in: try export(try captured()))
        XCTAssertEqual(event["parent_class"] as? String, "IOSurfaceRoot")
        XCTAssertTrue((event["driver_bundle_id"] as? String)?.hasPrefix("com.apple.") ?? false, "\(event)")
        XCTAssertEqual(event["parent_path"] as? String, IOKitRegistryServiceTests.surfaceRoot)
    }

    /// A record without them, eslogger's before and after message version 10 or Mac Monitor 2.1's, writes both keys
    /// as `null`, and opening it reads nothing from this Mac's registry, even for a path that's there.
    func testRecordsWithoutThemExportNull() throws {
        let legacy = try legacyRecord(ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN,
                                      ["user_client_class": "AppleAPFSUserClient", "user_client_type": 0])
        for record in [try esloggerOpen(), try esloggerOpen(version: 9), legacy] {
            let message = try importRecord(record)
            XCTAssertNil(message.event.iokit_open?.parent_class)
            XCTAssertNil(message.event.iokit_open?.driver_bundle_id)
            let event = try event("iokit_open", in: try export(message))
            XCTAssertTrue(event["parent_class"] is NSNull, "\(event)")
            XCTAssertTrue(event["driver_bundle_id"] is NSNull, "\(event)")
        }
    }

    /// The event store keeps both values as they were captured.
    func testStoreRoundTrip() throws {
        let message = try captured()
        try withEventStore([message]) { context, stored in
            context.refreshAllObjects()
            let event = try XCTUnwrap(stored[0].event.iokit_open)
            XCTAssertEqual(event.parent_class, message.event.iokit_open?.parent_class)
            XCTAssertEqual(event.driver_bundle_id, message.event.iokit_open?.driver_bundle_id)
            XCTAssertEqual(event.serviceName, "IOSurfaceRoot")
        }
    }

    // MARK: Wire and traces

    /// The wire carries both values, and a 3.0.0 Security Extension's message, which has neither key, decodes with
    /// none.
    func testWire() throws {
        let message = try captured()
        let decoded = try JSONDecoder().decode(Message.self, from: try wire(message))
        XCTAssertEqual(decoded.event.iokit_open?.parent_class, "IOSurfaceRoot")
        XCTAssertEqual(decoded.event.iokit_open?.driver_bundle_id, message.event.iokit_open?.driver_bundle_id)

        var object = try jsonObject(try wire(message))
        object[path: "event", "iokit_open", "_0", "parent_class"] = nil
        object[path: "event", "iokit_open", "_0", "driver_bundle_id"] = nil
        let legacy = try JSONDecoder().decode(Message.self, from: try JSONSerialization.data(withJSONObject: object))
        XCTAssertEqual(legacy.event.iokit_open?.user_client_class, "IOSurfaceRootUserClient")
        XCTAssertNil(legacy.event.iokit_open?.parent_class)
        XCTAssertNil(legacy.event.iokit_open?.driver_bundle_id)
    }

    /// An export opened as a trace keeps both values and exports them again the same.
    func testExportReopens() throws {
        let first = try export(opening(try captured(), driver: "com.example.driver"))
        let reopened = try importRecord(first)
        XCTAssertEqual(reopened.event.iokit_open?.parent_class, "IOSurfaceRoot")
        XCTAssertEqual(reopened.event.iokit_open?.driver_bundle_id, "com.example.driver")
        XCTAssertEqual(try event("iokit_open", in: try export(reopened)) as NSDictionary,
                       try event("iokit_open", in: first) as NSDictionary)
    }

    // MARK: Schema, predicates and indicators

    /// Exports with both values, with neither, and before message version 10, follow the telemetry schema.
    func testExportsFollowSchema() throws {
        let exports = [("captured", try captured()), ("eslogger", try importRecord(try esloggerOpen())),
                       ("eslogger version 9", try importRecord(try esloggerOpen(version: 9)))]
        assertValid(exports.map { ($0.0, exportText($0.1)) }, with: try generatedValidator())
    }

    /// Predicates can use both values, as searches and `macmonitor stream --predicate` do.
    func testPredicatesUseThem() throws {
        let record = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(exportText(try captured()).utf8))
                                   as? NSDictionary)
        for source in ["event.iokit_open.parent_class == 'IOSurfaceRoot'",
                       "event.iokit_open.driver_bundle_id BEGINSWITH 'com.apple.'"] {
            XCTAssertTrue(try StreamFilter.Predicate(source).evaluate(on: record), source)
        }
    }

    /// Non-Apple driver opened matches an open whose driver is known and isn't Apple's, on its record and on the
    /// stored event alike, and not an Apple driver's, an unknown one, or another event.
    func testNonAppleDriverIndicator() throws {
        let indicator = try XCTUnwrap(Indicator.defaults.first { $0.name == "Non-Apple driver opened" })
        XCTAssertEqual(indicator.id, UUID(uuidString: "6D4D0F1D-0000-4000-8000-000000000029"))
        XCTAssertEqual(indicator.predicate, Indicator.nonAppleDriverPredicate)
        let predicate = try StreamFilter.Predicate(indicator.predicate, for: .indicator)
        XCTAssertTrue(StoredEventValues.canEvaluate(predicate.parsed))

        let base = try captured()
        let cases: [(String?, Bool)] = [("com.example.driver", true), ("com.applesauce.driver", true),
                                        ("com.apple.iokit.IOSurface", false), ("", false), (nil, false)]
        let messages = cases.map { opening(base, driver: $0.0) }
        for ((driver, expected), message) in zip(cases, messages) {
            let record = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(exportText(message).utf8))
                                       as? NSDictionary)
            XCTAssertEqual(try predicate.evaluate(on: record), expected, driver ?? "nil")
        }
        try withEventStore(messages) { _, stored in
            for ((driver, expected), event) in zip(cases, stored) {
                XCTAssertEqual(IndicatorMatcher([indicator]).matches(event).isEmpty, !expected, driver ?? "nil")
            }
        }
        /// Another event's record doesn't match: a record has only its own type's payload.
        let other: NSDictionary = ["es_event_type": "ES_EVENT_TYPE_NOTIFY_OPEN",
                                   "event": ["open": ["file": ["path": "/dev/com.example.driver"]]]]
        XCTAssertFalse(try predicate.evaluate(on: other))
    }
}
