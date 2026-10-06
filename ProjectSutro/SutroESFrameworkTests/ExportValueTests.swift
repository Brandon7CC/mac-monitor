//
//  ExportValueTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Values eslogger writes
/// Pins exported values Mac Monitor used to write differently from eslogger: an `st_ino` of 2^63 or more (written
/// negative), a rename's new path `mode` (written 0; a rename has none), `iokit_open`'s parent fields before message
/// version 10 (written 0 and `null`; Endpoint Security has neither), a login's `uid` (written 0 without one, and lost
/// from eslogger's records, which have no `has_uid`), and a petition's `right_count` (written 0).
final class ExportValueTests: XCTestCase {
    /// The `st_ino` in the open fixture's file.
    private static let fixtureInode = #""st_ino":2002"#
    
    // MARK: st_ino
    
    /// The open fixture with its file's `st_ino` replaced, as JSON text so that every digit is kept.
    ///
    /// - Parameter inode: The new value's digits.
    /// - Returns: The record.
    /// - Throws: The error reading the fixture.
    private func openRecord(inode: String) throws -> String {
        let text = String(decoding: try fixture("eslogger-open.jsonl"), as: UTF8.self)
        XCTAssertTrue(text.contains(Self.fixtureInode))
        return text.replacingOccurrences(of: Self.fixtureInode, with: #""st_ino":"# + inode)
    }
    
    /// An inode number of 2^63 or more is kept by bit pattern and exported unsigned, as eslogger writes it.
    ///
    /// - Throws: The error reading the record.
    func testLargeInodeRoundTrip() throws {
        for inode in ["9223372036854775813", "18446744073709551615", "1152921500312605282"] {
            let message = try importRecord(try openRecord(inode: inode))
            guard case .open(let open) = message.event else { return XCTFail("Expected an open event") }
            XCTAssertEqual(open.file.stat.st_ino, Int64(bitPattern: UInt64(inode)!), inode)
            XCTAssertTrue(exportText(message).contains(#""st_ino":"# + inode), inode)
        }
    }
    
    /// Mac Monitor used to export such an inode as a negative number: it's read back and exported unsigned.
    ///
    /// - Throws: The error reading the record.
    func testNegativeInodeIsExportedUnsigned() throws {
        let message = try importRecord(try openRecord(inode: "-9223372036854775803"))
        XCTAssertTrue(exportText(message).contains(#""st_ino":9223372036854775813"#))
    }
    
    /// The Security Extension's inode number exports unsigned too.
    func testCapturedLargeInode() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OPEN)
        let file = fixture.file("/private/tmp/example/report.txt")
        file.pointee.stat.st_ino = 9_223_372_036_854_775_813
        fixture.message.pointee.event.open.file = file
        XCTAssertTrue(exportText(Message(from: fixture.raw)).contains(#""st_ino":9223372036854775813"#))
    }
    
    // MARK: New path mode
    
    /// A new path's object in a create or rename event: a directory and a file name.
    ///
    /// - Parameter mode: The `mode`, or `nil` for none.
    /// - Returns: The object.
    private func newPath(mode: Int?) -> [String: Any] {
        var path: [String: Any] = ["dir": ["path": "/private/tmp/example", "path_truncated": false, "stat": [:]],
                                   "filename": "b.txt"]
        path["mode"] = mode
        return path
    }
    
    /// The exported new path of a create or rename event.
    ///
    /// - Parameters:
    ///   - name: `create` or `rename`.
    ///   - record: The record.
    /// - Returns: The new path's object.
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no such event.
    private func exportedNewPath(_ name: String, _ record: [String: Any]) throws -> [String: Any]? {
        let event = try event(name, in: try export(try importRecord(record)))
        return (event["destination"] as? [String: Any])?["new_path"] as? [String: Any]
    }
    
    /// A rename's new path has no `mode`, so none is exported.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no rename event.
    func testRenameNewPathHasNoMode() throws {
        let rename: [String: Any] = [
            "source": ["path": "/private/tmp/example/a.txt", "path_truncated": false, "stat": [:]],
            "destination_type": 1, "destination": ["new_path": newPath(mode: nil)],
        ]
        let path = try exportedNewPath("rename", try esloggerRecord("rename", type: 25, rename))
        XCTAssertEqual(path?.keys.sorted(), ["dir", "filename"])
    }
    
    /// Mac Monitor up to 2.1.0 wrote a rename's `mode` as 0: it's dropped.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no rename event.
    func testMacMonitor21RenameModeIsDropped() throws {
        let record = try legacyRecord("rename", type: ES_EVENT_TYPE_NOTIFY_RENAME, [
            "source": ["path": "/private/tmp/example/a.txt", "path_truncated": false, "stat": [:]],
            "destination_type": 1, "destination_type_string": "ES_DESTINATION_TYPE_NEW_PATH",
            "destination": ["new_path": newPath(mode: 0)], "destination_path": "/private/tmp/example/b.txt",
        ])
        XCTAssertNil(try exportedNewPath("rename", record)?["mode"])
    }
    
    /// A create's new path keeps its `mode`.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no create event.
    func testCreateNewPathKeepsMode() throws {
        let create: [String: Any] = ["destination_type": 1, "destination": ["new_path": newPath(mode: 420)],
                                     "acl": NSNull()]
        let path = try exportedNewPath("create", try esloggerRecord("create", type: 13, create))
        XCTAssertEqual(path?["mode"] as? Int, 420)
    }
    
    /// The Security Extension's rename has no `mode`, and its create keeps one.
    func testCapturedNewPathMode() {
        let rename = rawMessage(type: ES_EVENT_TYPE_NOTIFY_RENAME)
        rename.message.pointee.event.rename.source = rename.file("/private/tmp/example/a.txt")
        rename.message.pointee.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        rename.message.pointee.event.rename.destination.new_path.dir = rename.file("/private/tmp/example")
        rename.message.pointee.event.rename.destination.new_path.filename = rename.token("b.txt")
        XCTAssertFalse(exportText(Message(from: rename.raw)).contains(#""mode""#))
        
        let create = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CREATE)
        create.message.pointee.event.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        create.message.pointee.event.create.destination.new_path.dir = create.file("/private/tmp/example")
        create.message.pointee.event.create.destination.new_path.filename = create.token("b.txt")
        create.message.pointee.event.create.destination.new_path.mode = 0o644
        XCTAssertTrue(exportText(Message(from: create.raw)).contains(#""mode":420"#))
    }
    
    // MARK: IOKit parent
    
    /// An `iokit_open` record of a message version, read and exported.
    ///
    /// - Parameters:
    ///   - version: The message's version.
    ///   - parent: The parent fields to add to the event, if any.
    /// - Returns: The exported event's object.
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no `iokit_open` event.
    private func exportedIOKitOpen(version: Int, parent: [String: Any] = [:]) throws -> [String: Any] {
        let event = ["user_client_type": 0, "user_client_class": "IOHIDLibUserClient"].merging(parent) { $1 }
        let record = try esloggerRecord("iokit_open", type: 24, event, version: version)
        return try self.event("iokit_open", in: try export(try importRecord(record)))
    }
    
    /// Before message version 10 there are no parent fields, so none are exported.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export has no `iokit_open` event.
    func testIOKitParentBeforeVersion10() throws {
        let event = try exportedIOKitOpen(version: 9)
        XCTAssertNil(event["parent_registry_id"])
        XCTAssertNil(event["parent_path"])
        /// Mac Monitor used to write them for every version.
        let older = try exportedIOKitOpen(version: 8, parent: ["parent_registry_id": 0, "parent_path": NSNull()])
        XCTAssertNil(older["parent_registry_id"])
        XCTAssertNil(older["parent_path"])
    }
    
    /// From message version 10 both are exported, a `NULL` parent path as `null`.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export has no `iokit_open` event.
    func testIOKitParentFromVersion10() throws {
        let event = try exportedIOKitOpen(version: 10, parent: [
            "parent_registry_id": 4_294_968_147, "parent_path": "IOService:/AppleARMPE/example",
        ])
        XCTAssertEqual(event["parent_registry_id"] as? Int, 4_294_968_147)
        XCTAssertEqual(event["parent_path"] as? String, "IOService:/AppleARMPE/example")
        let null = try exportedIOKitOpen(version: 10, parent: ["parent_registry_id": 7, "parent_path": NSNull()])
        XCTAssertEqual(null["parent_registry_id"] as? Int, 7)
        XCTAssertTrue(null["parent_path"] is NSNull)
    }
    
    /// The Security Extension's event before version 10 has no parent fields either.
    func testCapturedIOKitParentBeforeVersion10() {
        let fixture = rawMessage(version: 9, type: ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN)
        fixture.message.pointee.event.iokit_open.user_client_class = fixture.token("IOHIDLibUserClient")
        let text = exportText(Message(from: fixture.raw))
        XCTAssertFalse(text.contains("parent_registry_id"), text)
        XCTAssertFalse(text.contains("parent_path"), text)
    }
    
    /// The Security Extension's event from version 10 has both: a NULL parent path is `null` beside its registry ID.
    func testCapturedIOKitParentFromVersion10() {
        let fixture = rawMessage(version: 10, type: ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN)
        fixture.message.pointee.event.iokit_open.user_client_class = fixture.token("IOHIDLibUserClient")
        fixture.message.pointee.event.iokit_open.parent_registry_id = 4_294_968_147
        let text = exportText(Message(from: fixture.raw))
        XCTAssertTrue(text.contains(#""parent_path":null,"parent_registry_id":4294968147"#), text)
    }
    
    // MARK: Login user IDs
    
    /// eslogger's login events without their `uid`, by key and type. eslogger writes no `has_uid`.
    private static let logins: [(name: String, type: es_event_type_t, event: [String: Any])] = [
        ("openssh_login", ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN,
         ["success": true, "result_type": 0, "source_address_type": 1, "source_address": "192.0.2.1",
          "username": "testuser"]),
        ("login_login", ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN,
         ["success": true, "failure_message": NSNull(), "username": "testuser"]),
    ]
    
    /// A login's `uid` in an eslogger record is read back and exported as eslogger wrote it: a number, one of 2^31 or
    /// more included, or `null`.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export has no such event.
    func testLoginUIDRoundTrip() throws {
        for (name, type, event) in Self.logins {
            for uid: Any in [501, 4_294_967_294, NSNull()] {
                var object = event
                object["uid"] = uid
                let record = try esloggerRecord(name, type: Int(type.rawValue), object)
                let exported = try self.event(name, in: try export(try importRecord(record)))
                XCTAssertEqual(exported["uid"] as? NSObject, uid as? NSObject, "\(name) \(uid)")
                XCTAssertEqual(exported["has_uid"] as? Bool, !(uid is NSNull), "\(name) \(uid)")
            }
        }
    }
    
    /// The Security Extension's `login_login` without a user ID exports `null`, as eslogger writes it, not root's 0;
    /// and so does an older Security Extension's, which sent -1 in its place.
    ///
    /// - Throws: The error encoding or decoding the message, or an `XCTest` failure if an export has no such event.
    func testLoginWithoutUID() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN)
        var login = es_event_login_login_t()
        login.username = fixture.token("testuser")
        fixture.message.pointee.event.login_login = fixture.pointer(login)
        let captured = Message(from: fixture.raw)
        
        let json = try JSONEncoder().encode(captured)
        var sent = try XCTUnwrap(try JSONSerialization.jsonObject(with: json) as? [String: Any])
        var event = try XCTUnwrap((sent["event"] as? [String: Any])?["login_login"] as? [String: Any])
        var payload = try XCTUnwrap(event["_0"] as? [String: Any])
        payload["uid"] = -1
        event["_0"] = payload
        sent["event"] = ["login_login": event]
        let older = try JSONDecoder().decode(Message.self, from: JSONSerialization.data(withJSONObject: sent))
        
        for message in [captured, older] {
            let exported = try self.event("login_login", in: try export(message))
            XCTAssertTrue(exported["uid"] is NSNull, "\(exported)")
            XCTAssertEqual(exported["uid_human"] as? String, "Unknown")
        }
    }
    
    // MARK: Authorization petition
    
    /// A petition's `right_count` is exported as eslogger writes it, the number of rights, whether the petition was
    /// read from eslogger's record or captured.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if an export has no petition.
    func testPetitionRightCount() throws {
        let rights = ["system.privilege.admin", "system.preferences"]
        let type = ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION
        let record = try esloggerRecord("authorization_petition", type: Int(type.rawValue), [
            "instigator": NSNull(), "petitioner": NSNull(), "flags": 0, "right_count": 2, "rights": rights,
        ])
        
        let fixture = rawMessage(type: type)
        let petition = fixture.allocate(es_event_authorization_petition_t.self)
        let tokens = fixture.allocate(es_string_token_t.self, count: rights.count)
        rights.enumerated().forEach { tokens[$0] = fixture.token($1) }
        petition.pointee.rights = tokens
        petition.pointee.right_count = rights.count
        fixture.message.pointee.event.authorization_petition = petition
        
        for message in [try importRecord(record), Message(from: fixture.raw)] {
            let exported = try event("authorization_petition", in: try export(message))
            XCTAssertEqual(exported["right_count"] as? Int, 2)
            XCTAssertEqual(exported["rights"] as? [String], rights)
        }
    }
}
