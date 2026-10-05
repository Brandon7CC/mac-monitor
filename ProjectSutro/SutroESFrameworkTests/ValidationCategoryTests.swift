//
//  ValidationCategoryTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Code signing validation category
/// Pins a process's `cs_validation_category`: Endpoint Security's from message version 10 (`ESMessageCore.h`), so
/// eslogger writes no such key before it. Mac Monitor exported 0 (`ES_CS_VALIDATION_CATEGORY_INVALID`) for older
/// messages whenever the exporting Mac ran macOS 14 or later, and nothing at all on macOS 13.
final class ValidationCategoryTests: XCTestCase {
    /// The exported process of an exit message captured with a validation category in its process's bytes.
    ///
    /// - Parameter version: The message's version.
    /// - Returns: The exported process.
    /// - Throws: An `XCTest` failure if the export has no process.
    private func capturedProcess(version: UInt32) throws -> [String: Any] {
        let fixture = rawMessage(version: version, type: ES_EVENT_TYPE_NOTIFY_EXIT)
        fixture.message.pointee.process.pointee.cs_validation_category = ES_CS_VALIDATION_CATEGORY_PLATFORM
        return try XCTUnwrap(try export(Message(from: fixture.raw))["process"] as? [String: Any])
    }
    
    /// The exported process of a record read as File > Open Trace… reads it.
    ///
    /// - Parameter record: The record.
    /// - Returns: The exported process.
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no process.
    private func importedProcess(_ record: [String: Any]) throws -> [String: Any] {
        try XCTUnwrap(try export(try importRecord(record))["process"] as? [String: Any])
    }
    
    /// A record whose process has another validation category, or none.
    ///
    /// - Parameters:
    ///   - record: The record.
    ///   - version: The message's version.
    ///   - category: The category, or `nil` to leave the key out.
    /// - Returns: The record.
    /// - Throws: An `XCTest` failure if the record has no process.
    private func record(_ record: [String: Any], version: Int, category: Int?) throws -> [String: Any] {
        var record = record
        var process = try XCTUnwrap(record["process"] as? [String: Any])
        process["cs_validation_category"] = category
        record["process"] = process
        record["version"] = version
        return record
    }
    
    /// Before message version 10 the bytes aren't a category, so none is exported.
    ///
    /// - Throws: An `XCTest` failure if the export has no process.
    func testCapturedBeforeVersion10() throws {
        let process = try capturedProcess(version: 9)
        XCTAssertNil(process["cs_validation_category"])
        XCTAssertNil(process["cs_validation_category_string"])
    }
    
    /// From message version 10 the category is exported with its name.
    ///
    /// - Throws: An `XCTest` failure if the export has no process.
    func testCapturedFromVersion10() throws {
        let process = try capturedProcess(version: 10)
        XCTAssertEqual(process["cs_validation_category"] as? Int, Int(ES_CS_VALIDATION_CATEGORY_PLATFORM.rawValue))
        XCTAssertEqual(process["cs_validation_category_string"] as? String, "ES_CS_VALIDATION_CATEGORY_PLATFORM")
    }
    
    /// An eslogger record before message version 10 has no category, and neither has its export. Nor has a Mac
    /// Monitor 2.1 export of one, which wrote 0.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export has no process.
    func testImportedBeforeVersion10() throws {
        let eslogger = try record(try fixtureObject("eslogger-exit.jsonl"), version: 9, category: nil)
        XCTAssertNil(try importedProcess(eslogger)["cs_validation_category"])
        var legacy = try record(try fixtureObject("macmonitor-2.1-exit.jsonl"), version: 8, category: 0)
        var process = try XCTUnwrap(legacy["process"] as? [String: Any])
        process["cs_validation_category_string"] = nil
        legacy["process"] = process
        XCTAssertNil(try importedProcess(legacy)["cs_validation_category"])
    }
    
    /// From message version 10 an opened trace's category is exported as it was recorded.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export has no process.
    func testImportedFromVersion10() throws {
        let eslogger = try record(try fixtureObject("eslogger-exit.jsonl"), version: 10, category: 0)
        XCTAssertEqual(try importedProcess(eslogger)["cs_validation_category"] as? Int, 0)
        let legacy = try importedProcess(try fixtureObject("macmonitor-2.1-exit.jsonl"))
        XCTAssertEqual(legacy["cs_validation_category"] as? Int, 1)
        XCTAssertEqual(legacy["cs_validation_category_string"] as? String, "ES_CS_VALIDATION_CATEGORY_PLATFORM")
    }
}
