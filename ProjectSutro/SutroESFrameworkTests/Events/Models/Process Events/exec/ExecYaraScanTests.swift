//
//  ExecYaraScanTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The scan of an exec's script
/// Pins an exec's `yara_scan`, what scanning the script it runs found: the schema has it as an optional enrichment
/// with a close's definition, it reads back from a trace, the app's store and an export as it was, an exec without
/// one has none, and an indicator reads it.
final class ExecYaraScanTests: XCTestCase {
    /// The schema has `event.exec.yara_scan` as Mac Monitor's own optional key, with the definition a close's scan
    /// has, so a rule compares its fields.
    func testTheSchemaHasIt() throws {
        let root = try jsonObject(try TelemetrySchema.data())
        let exec = try XCTUnwrap(root[path: "$defs", "exec_event"] as? [String: Any])
        let key = try XCTUnwrap(exec[path: "properties", "yara_scan"] as? [String: Any])
        XCTAssertEqual(key["$ref"] as? String, "#/$defs/yara_scan")
        XCTAssertEqual(key["x-mac-monitor-origin"] as? String, "mac-monitor")
        XCTAssertFalse((exec["required"] as? [String] ?? []).contains("yara_scan"))
        XCTAssertEqual(RecordSchema.lookup("event.exec.yara_scan.rules"), .kind(.strings))
        XCTAssertEqual(RecordSchema.lookup("event.exec.yara_scan.status"), .kind(.string))
    }

    /// An exec's scan reads back from its record, is kept by the app's store, and exports as it was. One without
    /// a scan exports no key.
    func testItTravelsThroughTheStoreAndExports() throws {
        let message = try TraceImporter.message(from: try scannedRecord("ES_EVENT_TYPE_NOTIFY_EXEC"))
        guard case .exec(let exec) = message.event else { return XCTFail("Not an exec") }
        XCTAssertEqual(exec.yara_scan, Self.matchedScan)
        withStoredEvent(message) { stored in
            XCTAssertEqual(stored.event.exec?.yara_scan, Self.matchedScan)
        }
        let exported = try event("exec", in: try export(message))
        XCTAssertEqual(exported[path: "yara_scan", "rules"] as? [String], [Self.matchedRule])
        XCTAssertEqual(exported[path: "yara_scan", "status"] as? String, YaraScan.scanned)

        let unscanned = try TraceImporter.message(from: try scannedRecord("ES_EVENT_TYPE_NOTIFY_EXEC", scan: nil))
        XCTAssertNil(try event("exec", in: try export(unscanned))["yara_scan"])
    }

    /// A rule on an exec's scan reads it, and its hit lists the XProtect rule that matched.
    func testAnIndicatorReadsIt() throws {
        let rule = ownIndicator("Script matched", #"event.exec != nil AND ANY event.exec.yara_scan.rules != """#)
        let indicators = CompiledIndicators([rule])
        XCTAssertEqual(indicators.problems.map(\.reason), [])
        XCTAssertTrue(indicators.readsYaraScan)
        var values = MessageValueCache()
        let message = try TraceImporter.message(from: try scannedRecord("ES_EVENT_TYPE_NOTIFY_EXEC"))
        let hits = indicators.evaluate(message, values: &values).hits
        XCTAssertEqual(hits.map(\.id), [rule.id])
        XCTAssertEqual(hits.first?.matched,
                       [IndicatorMatchedField(field: "event.exec.yara_scan.rules", value: .string(Self.matchedRule))])
        let unscanned = try TraceImporter.message(from: try scannedRecord("ES_EVENT_TYPE_NOTIFY_EXEC", scan: nil))
        XCTAssertEqual(indicators.evaluate(unscanned, values: &values).hits.map(\.id), [])
    }
}
