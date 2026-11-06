//
//  LaunchItemBundleExportTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Launch item bundles in the store, the export, the wire and traces
/// Pins `item.bundle` and `item.app_bundle` from capture to export: the event store keeps them, the export always
/// writes both keys (`null` when there's no bundle) and follows the schema, the wire carries them, a 3.0.0 Security
/// Extension's message and a 3.0.0 trace without them decode with none, and opening a trace never reads a bundle.
final class LaunchItemBundleExportTests: XCTestCase {
    /// The keys of an exported bundle, in the order the export writes them.
    private static let bundleKeys = ["path", "info_plist_path", "identifier", "name", "version", "short_version",
                                     "executable_path", "is_ui_element", "is_background_only", "signing_id", "team_id",
                                     "codesigning_type", "is_quarantined", "where_froms", "birth_time", "age_ms"]
    /// The download origins the test's helper has.
    private static let origins = ["https://example.com/Parent.zip", "https://example.com/"]

    /// A login item add, captured as the Security Extension captures it, 3 s after its app was created: a downloaded
    /// app (quarantined, with where-froms) and its helper.
    ///
    /// - Parameter type: Add or remove.
    /// - Returns: The event.
    /// - Throws: The error making the bundles.
    private func captured(_ type: es_event_type_t = ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD) throws -> Message {
        let app = try makeBundle("Parent.app")
        try makeBundle("Contents/Library/LoginItems/Helper.app", in: URL(fileURLWithPath: app))
        quarantine(app)
        try setWhereFroms(Self.origins, on: app)
        var info = stat()
        XCTAssertEqual(stat(app, &info), 0)
        return message(for: rawLaunchItem(ES_BTM_ITEM_TYPE_LOGIN_ITEM, url: "Contents/Library/LoginItems/Helper.app",
                                          appURL: fileURL(app)), type,
                       at: timespec(tv_sec: info.st_birthtimespec.tv_sec + 3, tv_nsec: info.st_birthtimespec.tv_nsec))
    }

    /// A launch item event, captured as the Security Extension captures it.
    ///
    /// - Parameters:
    ///   - item: The event's item.
    ///   - type: Add or remove.
    ///   - time: The message's time, or the fixture's.
    /// - Returns: The event.
    private func message(for item: es_btm_launch_item_t,
                         _ type: es_event_type_t = ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
                         at time: timespec? = nil) -> Message {
        let fixture = rawMessage(type: type)
        if let time { fixture.message.pointee.time = time }
        let item = fixture.pointer(item)
        if type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD {
            let event = fixture.allocate(es_event_btm_launch_item_add_t.self)
            event.pointee.item = item
            fixture.message.pointee.event.btm_launch_item_add = event
        } else {
            let event = fixture.allocate(es_event_btm_launch_item_remove_t.self)
            event.pointee.item = item
            fixture.message.pointee.event.btm_launch_item_remove = event
        }
        return Message(from: fixture.raw)
    }

    /// A launch item event's item object in an export.
    ///
    /// - Parameter export: The export.
    /// - Returns: `event.<name>.item`.
    /// - Throws: An `XCTest` failure if the export has no launch item.
    private func item(in export: [String: Any]) throws -> [String: Any] {
        let events = try XCTUnwrap(export["event"] as? [String: Any])
        let event = try XCTUnwrap((events["btm_launch_item_add"] ?? events["btm_launch_item_remove"]) as? [String: Any])
        return try XCTUnwrap(event["item"] as? [String: Any])
    }

    /// The item object of a launch item add, as eslogger writes it, naming Calculator.
    private static let esloggerItem: [String: Any] = [
        "item_type": Int(ES_BTM_ITEM_TYPE_APP.rawValue), "legacy": false, "managed": false, "uid": 501,
        "app_url": NSNull(), "item_url": "file:///System/Applications/Calculator.app/",
    ]

    // MARK: Export

    /// A captured add exports both bundles with every key, the app's provenance and its age at the event.
    func testCapturedBundlesExport() throws {
        let message = try captured()
        let item = try item(in: try export(message))
        let bundle = try XCTUnwrap(item["bundle"] as? [String: Any])
        let app = try XCTUnwrap(item["app_bundle"] as? [String: Any])
        XCTAssertEqual(Set(bundle.keys), Set(Self.bundleKeys))
        XCTAssertEqual(Set(app.keys), Set(Self.bundleKeys))
        XCTAssertEqual((bundle["path"] as? String)?.hasSuffix("/Parent.app/Contents/Library/LoginItems/Helper.app"),
                       true)
        XCTAssertEqual(bundle["identifier"] as? String, "com.example.helper")
        XCTAssertEqual(bundle["is_ui_element"] as? Bool, true)
        XCTAssertTrue(bundle["team_id"] is NSNull)
        XCTAssertEqual(app["codesigning_type"] as? String, "UNSIGNED")
        XCTAssertEqual(app["is_quarantined"] as? Int, 1)
        XCTAssertEqual(app["where_froms"] as? [String], Self.origins)
        XCTAssertEqual(app["age_ms"] as? Int, 3_000)
        let birth = try XCTUnwrap(app["birth_time"] as? String)
        XCTAssertNotNil(birth.range(of: SchemaPattern.timespec.rawValue, options: .regularExpression), birth)
        XCTAssertTrue((item["plist_contents"] as? String)?.contains("com.example.helper") ?? false)
    }

    /// An item without bundles writes both keys as `null`.
    func testMissingBundlesExportNull() throws {
        let item = try item(in: try export(try importRecord(try esloggerRecord(ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
            ["instigator": NSNull(), "app": NSNull(), "item": Self.esloggerItem, "executable_path": NSNull()]))))
        XCTAssertTrue(item["bundle"] is NSNull, "\(item)")
        XCTAssertTrue(item["app_bundle"] is NSNull, "\(item)")
    }

    /// The event store keeps both bundles as they were captured, and a remove's too.
    func testStoreRoundTrip() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        for message in [try captured(), try captured(ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE)] {
            let item: LaunchItem
            switch message.event {
            case .btm_launch_item_add(let add): item = add.item
            case .btm_launch_item_remove(let remove): item = remove.item
            default: return XCTFail("Not a launch item event")
            }
            try withEventStore([message]) { context, stored in
                context.refreshAllObjects()
                let event = stored[0].event
                let storedItem = try XCTUnwrap(event.btm_launch_item_add?.item ?? event.btm_launch_item_remove?.item)
                XCTAssertEqual(try encoder.encode(storedItem.bundle), try encoder.encode(item.bundle))
                XCTAssertEqual(try encoder.encode(storedItem.app_bundle), try encoder.encode(item.app_bundle))
                XCTAssertEqual(storedItem.plistPath, item.bundle.map { $0.path + "/Contents/Info.plist" })
                XCTAssertEqual(storedItem.plistPath, item.bundle?.info_plist_path)
            }
        }
    }

    /// The PLIST tab names the plist that was read: a shallow bundle's Info.plist at its top, also without an
    /// executable, and an `SMAppService` agent's plist by its full path, as it was read relative to its app.
    func testPlistPaths() throws {
        var info = Self.exampleInfo
        info["CFBundleExecutable"] = nil
        let shallow = try makeBundle("Helper.bundle", info: info, shallow: true)
        let app = try makeBundle("Parent.app")
        let agents = app + "/Contents/Library/LaunchAgents"
        try FileManager.default.createDirectory(atPath: agents, withIntermediateDirectories: true)
        try PropertyListSerialization.data(fromPropertyList: ["Label": "com.example.agent"], format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: agents + "/com.example.agent.plist"))
        let messages = [message(for: rawLaunchItem(ES_BTM_ITEM_TYPE_USER_ITEM, url: fileURL(shallow))),
                        message(for: rawLaunchItem(ES_BTM_ITEM_TYPE_AGENT,
                                                   url: "Contents/Library/LaunchAgents/com.example.agent.plist",
                                                   appURL: fileURL(app)))]
        try withEventStore(messages) { context, stored in
            context.refreshAllObjects()
            let items = stored.compactMap { $0.event.btm_launch_item_add?.item }
            let user = try XCTUnwrap(items.first { $0.item_type == Int16(ES_BTM_ITEM_TYPE_USER_ITEM.rawValue) })
            XCTAssertEqual(user.plistPath, shallow + "/Info.plist")
            XCTAssertNotNil(user.plist_contents)
            let agent = try XCTUnwrap(items.first { $0.item_type == Int16(ES_BTM_ITEM_TYPE_AGENT.rawValue) })
            XCTAssertEqual(agent.plistPath, agents + "/com.example.agent.plist")
            XCTAssertNotNil(agent.plist_contents)
        }
    }

    // MARK: Wire and traces

    /// The wire carries both bundles, and a 3.0.0 Security Extension's message, which has neither key, decodes with
    /// none.
    func testWire() throws {
        let message = try captured()
        let decoded = try JSONDecoder().decode(Message.self, from: try wire(message))
        guard case .btm_launch_item_add(let add) = decoded.event else { return XCTFail("Not an add") }
        XCTAssertEqual(add.item.bundle?.identifier, "com.example.helper")
        XCTAssertEqual(add.item.app_bundle?.where_froms, Self.origins)
        XCTAssertEqual(add.item.app_bundle?.age_ms, 3_000)

        var object = try jsonObject(try wire(message))
        object[path: "event", "btm_launch_item_add", "_0", "item", "bundle"] = nil
        object[path: "event", "btm_launch_item_add", "_0", "item", "app_bundle"] = nil
        let legacy = try JSONDecoder().decode(Message.self, from: try JSONSerialization.data(withJSONObject: object))
        guard case .btm_launch_item_add(let old) = legacy.event else { return XCTFail("Not an add") }
        XCTAssertNil(old.item.bundle)
        XCTAssertNil(old.item.app_bundle)
    }

    /// An export opened as a trace keeps both bundles, their birth times and ages, and exports them again the same.
    func testExportReopens() throws {
        let first = try export(try captured())
        let reopened = try importRecord(first)
        guard case .btm_launch_item_add(let add) = reopened.event else { return XCTFail("Not an add") }
        XCTAssertEqual(add.item.app_bundle?.codesigning_type, .unsigned)
        XCTAssertEqual(add.item.app_bundle?.age_ms, 3_000)
        XCTAssertNotNil(add.item.app_bundle?.birth_time)
        XCTAssertEqual(try item(in: try export(reopened))["app_bundle"] as? NSDictionary,
                       try item(in: first)["app_bundle"] as? NSDictionary)
        XCTAssertEqual(try item(in: try export(reopened))["bundle"] as? NSDictionary,
                       try item(in: first)["bundle"] as? NSDictionary)
    }

    /// Opening a trace derives a bundle's age from its birth time when the record gives none, and keeps a record's
    /// own, a negative one included.
    func testOpeningDerivesBundleAges() throws {
        var record = try export(try captured())
        record[path: "event", "btm_launch_item_add", "item", "app_bundle", "age_ms"] = NSNull()
        record[path: "event", "btm_launch_item_add", "item", "bundle", "age_ms"] = NSNull()
        guard case .btm_launch_item_add(let derived) = try importRecord(record).event else {
            return XCTFail("Not an add")
        }
        XCTAssertEqual(derived.item.app_bundle?.age_ms, 3_000)
        let helperAge = try XCTUnwrap(derived.item.bundle?.age_ms, "The helper's age is derived too")
        XCTAssertTrue((0...3_000).contains(helperAge), "The helper was made just after its app: \(helperAge)")

        record[path: "event", "btm_launch_item_add", "item", "app_bundle", "age_ms"] = -5
        guard case .btm_launch_item_add(let kept) = try importRecord(record).event else {
            return XCTFail("Not an add")
        }
        XCTAssertEqual(kept.item.app_bundle?.age_ms, -5)
        XCTAssertNil(kept.item.app_bundle?.ageText, "A negative age is never shown")
    }

    /// A 3.0.0 trace and eslogger's record have no bundles, and opening them reads none from this Mac, even when the
    /// item names a bundle that's here.
    func testTracesWithoutBundlesReadNothing() throws {
        var item = Self.esloggerItem
        item["item_type_string"] = "ES_BTM_ITEM_TYPE_APP"
        item["item_path"] = "/System/Applications/Calculator.app"
        item["app_path"] = NSNull()
        var legacy = try legacyRecord(ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
                                      ["instigator": NSNull(), "app": NSNull(), "item": item,
                                       "executable_path": NSNull()])
        legacy[TelemetrySchema.versionKey] = "1.0.0"
        let eslogger = try esloggerRecord(ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
                                          ["instigator": NSNull(), "app": NSNull(), "item": Self.esloggerItem,
                                           "executable_path": NSNull()])
        for record in [legacy, eslogger] {
            let message = try importRecord(record)
            guard case .btm_launch_item_add(let add) = message.event else { return XCTFail("Not an add") }
            XCTAssertNil(add.item.bundle)
            XCTAssertNil(add.item.app_bundle)
            XCTAssertNil(add.item.plist_contents)
        }
    }

    // MARK: Schema and predicates

    /// Exports with bundles, with a remove's, and without, follow the telemetry schema.
    func testExportsFollowSchema() throws {
        let none = try importRecord(try esloggerRecord(ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
            ["instigator": NSNull(), "app": NSNull(), "item": Self.esloggerItem, "executable_path": NSNull()]))
        let exports = [("captured add", try captured()), ("captured remove",
                                                          try captured(ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE)),
                       ("eslogger", none)]
        assertValid(exports.map { ($0.0, exportText($0.1)) }, with: try generatedValidator())
    }

    /// Predicates can use the bundles, as searches and `macmonitor stream --predicate` do.
    func testPredicatesUseTheBundles() throws {
        let record = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(exportText(try captured()).utf8))
                                   as? NSDictionary)
        for source in ["event.btm_launch_item_add.item.bundle.is_ui_element == true",
                       "event.btm_launch_item_add.item.app_bundle.is_quarantined == 1",
                       "event.btm_launch_item_add.item.app_bundle.age_ms < 60000",
                       "ANY event.btm_launch_item_add.item.app_bundle.where_froms BEGINSWITH 'https://example.com'"] {
            XCTAssertTrue(try StreamFilter.Predicate(source).evaluate(on: record), source)
        }
        let platform = "event.btm_launch_item_add.item.bundle.codesigning_type == 'PLATFORM'"
        XCTAssertFalse(try StreamFilter.Predicate(platform).evaluate(on: record))
    }
}
