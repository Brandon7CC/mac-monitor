//
//  OpenDirectoryExportTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Open Directory events in eslogger's format
/// Pins that exports of Open Directory events have every key eslogger writes, with eslogger's value: the instigator's
/// process (or `null`), `instigator_token`, the member object, numeric record and account types, and `db_path` as
/// `null` when there's none. Mac Monitor's own fields are added beside them, and events exported before 2.2.0 are read
/// back with what they kept.
///
/// The golden records (`eslogger-od.jsonl`) are eslogger's output on macOS 27 (message version 10), scrubbed, plus
/// three synthetic ones: an `od_modify_password`, an `od_attribute_value_add` on a group, and an `od_group_remove` on
/// a directory node without a database.
final class OpenDirectoryExportTests: XCTestCase {
    /// eslogger's records.
    private static let esloggerFixture = "eslogger-od.jsonl"
    /// Mac Monitor's own fields of every Open Directory event.
    private static let commonAdditions = ["error_code_human", "instigator_process_name", "instigator_process_path",
                                          "instigator_process_signing_id", "instigator_process_audit_token"]
    /// Mac Monitor's own fields of each event, besides ``commonAdditions``.
    private static let additions = ["od_group_add": "member_string", "od_group_remove": "member_string",
                                    "od_attribute_value_add": "record_type_string",
                                    "od_modify_password": "account_type_string"]
    
    /// The only event of a record or export, and its name.
    ///
    /// - Parameter record: The record.
    /// - Returns: The event's key and object.
    /// - Throws: An `XCTest` failure if the record doesn't hold one event.
    private func onlyEvent(_ record: [String: Any]) throws -> (name: String, object: [String: Any]) {
        let events = try XCTUnwrap(record["event"] as? [String: Any])
        XCTAssertEqual(events.count, 1)
        let (name, object) = try XCTUnwrap(events.first)
        return (name, try XCTUnwrap(object as? [String: Any]))
    }
    
    /// A record captured as the Security Extension captures it (see ``XCTestCase/capture(eslogger:version:fill:)``).
    ///
    /// - Parameters:
    ///   - record: eslogger's record.
    ///   - version: The message's version, if not the record's.
    /// - Returns: The event.
    private func capture(_ record: [String: Any], version: UInt32? = nil) -> Message {
        capture(eslogger: record, version: version) { $0.fillODEvent(eslogger: record) }
    }
    
    // MARK: eslogger parity
    
    /// Each eslogger record, opened and exported, has every value eslogger wrote, at eslogger's key path.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if its export isn't a JSON object.
    func testImportedRecordsMatchESLogger() throws {
        let records = try fixtureRecords(Self.esloggerFixture)
        XCTAssertEqual(records.count, 11)
        for record in records {
            let name = try onlyEvent(record).name
            assertContains(record, try export(try importRecord(record)), ignoring: Self.esloggerSequenceNumbers, name)
        }
    }
    
    /// Each eslogger record, captured from Endpoint Security's structs and exported, has every value eslogger wrote.
    ///
    /// - Throws: An `XCTest` failure if an export isn't a JSON object.
    func testCapturedRecordsMatchESLogger() throws {
        for record in try fixtureRecords(Self.esloggerFixture) {
            let name = try onlyEvent(record).name
            assertContains(record, try export(capture(record)), ignoring: Self.esloggerSequenceNumbers, name)
        }
    }
    
    /// Mac Monitor's own fields are exported beside eslogger's: the instigator's name, path and signing ID are `null`
    /// only when Endpoint Security left the instigator out.
    ///
    /// - Throws: An `XCTest` failure if an export isn't a JSON object.
    func testAdditions() throws {
        for record in try fixtureRecords(Self.esloggerFixture) {
            let (name, object) = try onlyEvent(try export(try importRecord(record)))
            let hasInstigator = !(try onlyEvent(record).object["instigator"] is NSNull)
            for key in Self.commonAdditions + [Self.additions[name]].compactMap({ $0 }) {
                let nullable = !hasInstigator && key != "error_code_human" && key != "instigator_process_audit_token"
                    && Self.commonAdditions.contains(key)
                XCTAssertNotNil(object[key], "\(name).\(key)")
                XCTAssertEqual(object[key] is NSNull, nullable, "\(name).\(key)")
            }
        }
    }
    
    /// An instigator Endpoint Security left out is exported as `null`, as eslogger writes it, with its token.
    ///
    /// - Throws: An `XCTest` failure if the export isn't a JSON object.
    func testInstigatorLeftOut() throws {
        let record = try XCTUnwrap(try fixtureRecords(Self.esloggerFixture).first)
        for message in [try importRecord(record), capture(record)] {
            let event = try self.event("od_create_user", in: try export(message))
            XCTAssertTrue(event["instigator"] is NSNull)
            XCTAssertEqual((event["instigator_token"] as? [String: Any])?["pid"] as? Int, 4100)
            XCTAssertEqual(event["instigator_process_audit_token"] as? String,
                           "pid:4100, euid:0, ruid:0, rgid:0, egid:0, asid:100100, auid:501, pidversion:9100")
            XCTAssertTrue(event["instigator_process_name"] is NSNull)
        }
    }
    
    /// Before message version 8 Endpoint Security has no `instigator_token`: it's exported as `null`.
    ///
    /// - Throws: An `XCTest` failure if the export isn't a JSON object.
    func testVersion7HasNoInstigatorToken() throws {
        for record in try fixtureRecords(Self.esloggerFixture) {
            let (name, object) = try onlyEvent(try export(capture(record, version: 7)))
            XCTAssertTrue(object["instigator_token"] is NSNull, name)
        }
    }
    
    // MARK: Exports before 2.2.0
    
    /// The export of an Open Directory event from a Mac Monitor 2.1 export, which holds the legacy fixture's event.
    ///
    /// - Parameter name: The event's key.
    /// - Returns: The event's object.
    /// - Throws: The error reading a fixture or the record, or an `XCTest` failure if a fixture or the export has no
    ///   such event.
    private func reexportLegacy(_ name: String) throws -> [String: Any] {
        let events = try XCTUnwrap(try fixtureObject("macmonitor-2.1-od.json")["events"] as? [String: Any])
        let type = try XCTUnwrap(RawMessageFixture.openDirectoryEvents.first { $0.name == name }?.type)
        let record = try legacyRecord(name, type: type, try XCTUnwrap(events[name]))
        return try event(name, in: try export(try importRecord(record)))
    }
    
    /// An Open Directory event exported before 2.2.0 is exported again with the numbers its names stand for, the names
    /// kept in the `*_string` fields, and `null` for what it didn't keep.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export isn't a JSON object.
    func testLegacyExportsAreReadBack() throws {
        let attribute = try reexportLegacy("od_attribute_value_add")
        assertContains(["record_type": 1, "record_type_string": "GROUP", "instigator": NSNull(),
                        "instigator_token": NSNull(), "instigator_process_name": "dscl"], attribute, "attribute")
        
        let added = try reexportLegacy("od_group_add")
        assertContains(["member": ["member_type": 1, "member_value": NSNull()],
                        "member_string": "ES_OD_MEMBER_TYPE_USER_UUID"], added, "group add")
        
        let removed = try reexportLegacy("od_group_remove")
        assertContains(["member": NSNull(), "member_string": "UNKNOWN", "db_path": ""], removed, "group remove")
        
        let password = try reexportLegacy("od_modify_password")
        assertContains(["account_type": 1, "account_type_string": "ES_OD_ACCOUNT_TYPE_COMPUTER"], password, "password")
        
        let user = try reexportLegacy("od_create_user")
        assertContains(["error_code": 4102, "user_name": "testuser", "instigator_process_signing_id": "com.apple.dscl"],
                       user, "create user")
    }
    
    /// A 2.2.0 export reads back as it was exported.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export isn't a JSON object.
    func testExportsRoundTrip() throws {
        for record in try fixtureRecords(Self.esloggerFixture) {
            let exported = try export(try importRecord(record))
            let again = try export(try importRecord(exported))
            let (name, object) = try onlyEvent(exported)
            let reexported = try onlyEvent(again).object
            XCTAssertEqual(NSDictionary(dictionary: object), NSDictionary(dictionary: reexported), name)
        }
    }
}
