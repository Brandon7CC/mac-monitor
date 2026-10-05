//
//  OptionalStringTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Optional strings
/// Pins that a string the SDK calls optional is recorded and exported as eslogger writes it: `null` when Endpoint
/// Security leaves it out (`data` is `NULL`), and "" when it's empty. Mac Monitor used to write "" for the first, or
/// leave out the second.
final class OptionalStringTests: XCTestCase {
    // MARK: Capture
    
    /// An XProtect remediation without a path.
    func testRemediatedPath() {
        for text in [nil, "", "/Applications/Example.app"] {
            let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED)
            let event = fixture.allocate(es_event_xp_malware_remediated_t.self)
            event.pointee.remediated_path = fixture.token(text)
            fixture.message.pointee.event.xp_malware_remediated = event
            XCTAssertEqual(XProtecRemediateEvent(from: fixture.raw).remediated_path, text)
        }
    }
    
    /// An XProtect detection's empty executable path is kept.
    func testDetectedExecutable() {
        let fixture = rawMessage(version: 10, type: ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED)
        let event = fixture.allocate(es_event_xp_malware_detected_t.self)
        event.pointee.detected_path = fixture.token("/Applications/Example.app")
        event.pointee.detected_executable = fixture.token("")
        fixture.message.pointee.event.xp_malware_detected = event
        XCTAssertEqual(XProtectDetectEvent(from: fixture.raw).detected_executable, "")
    }
    
    /// A launch item without an executable path, and app URLs that are empty or aren't URLs.
    func testLaunchItemStrings() {
        for (executable, app) in [(String?.none, String?.none), ("", ""), ("/usr/bin/true", "not a url")] {
            let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD)
            let event = fixture.allocate(es_event_btm_launch_item_add_t.self)
            event.pointee.item = fixture.allocate(es_btm_launch_item_t.self)
            event.pointee.item.pointee.item_url = fixture.token("file:///Library/LaunchDaemons/com.example.agent.plist")
            event.pointee.item.pointee.app_url = fixture.token(app)
            event.pointee.executable_path = fixture.token(executable)
            fixture.message.pointee.event.btm_launch_item_add = event
            let add = LaunchItemAddEvent(from: fixture.raw)
            XCTAssertEqual(add.executable_path, executable)
            XCTAssertEqual(add.item.app_url, app)
        }
    }
    
    /// A login's failure message is read whatever `success` says, and kept when it's empty.
    func testLoginFailureMessage() {
        for (success, message) in [(true, String?.none), (false, ""), (false, "Authentication failed")] {
            let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN)
            let event = fixture.allocate(es_event_login_login_t.self)
            event.pointee.success = success
            event.pointee.failure_message = fixture.token(message)
            event.pointee.username = fixture.token("testuser")
            fixture.message.pointee.event.login_login = event
            XCTAssertEqual(LoginLoginEvent(from: fixture.raw).failure_message, message)
        }
    }
    
    /// A process's empty signing ID is kept, and a missing team ID stays missing.
    func testProcessSigningIDs() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
        let raw = fixture.process(path: "/usr/bin/true", signingID: "", teamID: nil)
        let process = Process(from: raw.pointee, version: 10)
        XCTAssertEqual(process.signing_id, "")
        XCTAssertNil(process.team_id)
    }
    
    /// A Gatekeeper override's file without a team ID, and a path arm without a path.
    func testGatekeeperStrings() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE)
        let override = fixture.allocate(es_event_gatekeeper_user_override_t.self)
        override.pointee.file_type = ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_FILE
        override.pointee.file.file = fixture.file("/Applications/Example.app/Contents/MacOS/Example")
        override.pointee.signing_info = fixture.allocate(es_signed_file_info_t.self)
        override.pointee.signing_info?.pointee.signing_id = fixture.token("com.example.app")
        fixture.message.pointee.event.gatekeeper_user_override = override
        let event = GatekeeperUserOverrideEvent(from: fixture.raw)
        XCTAssertEqual(event.signing_info?.signing_id, "com.example.app")
        XCTAssertNil(event.signing_info?.team_id)
        
        override.pointee.file_type = ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH
        override.pointee.file.file_path = fixture.token(nil)
        XCTAssertEqual(FilePathUnion.from(override: override.pointee), .unknown)
        override.pointee.file.file_path = fixture.token("/Applications/Example.app")
        XCTAssertEqual(FilePathUnion.from(override: override.pointee), .file_path("/Applications/Example.app"))
    }
    
    /// An authorization petition's empty right is kept, as eslogger keeps every one.
    func testPetitionRights() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION)
        let event = fixture.allocate(es_event_authorization_petition_t.self)
        let rights = fixture.allocate(es_string_token_t.self, count: 2)
        rights[0] = fixture.token("system.privilege.admin")
        rights[1] = fixture.token("")
        event.pointee.rights = rights
        event.pointee.right_count = 2
        fixture.message.pointee.event.authorization_petition = event
        XCTAssertEqual(AuthorizationPetitionEvent(from: fixture.raw).rights, ["system.privilege.admin", ""])
    }
    
    // MARK: Read back and exported
    
    /// Import an eslogger record with `value` in its event, export it, and read the exported value at `path`.
    ///
    /// - Parameters:
    ///   - name: The event's key.
    ///   - type: The event's `event_type`.
    ///   - event: The event's object, with `value` already in place.
    ///   - path: The keys to the value in the exported event.
    /// - Returns: The exported value: `NSNull` for `null`, `nil` if a key is missing.
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no such event.
    private func exported(_ name: String, type: Int, _ event: [String: Any], at path: [String]) throws -> Any? {
        let export = try export(try importRecord(try esloggerRecord(name, type: type, event)))
        return path.reduce(try self.event(name, in: export) as Any?) { ($0 as? [String: Any])?[$1] }
    }
    
    /// Assert that `null` and "" in an eslogger record come back out of the export as they went in.
    ///
    /// - Parameters:
    ///   - name: The event's key.
    ///   - type: The event's `event_type`.
    ///   - path: The keys to the value in the exported event.
    ///   - event: Builds the event's object around a value.
    ///   - line: The caller's line.
    /// - Throws: The error reading a record, or an `XCTest` failure if an export has no such event.
    private func assertKeepsNullAndEmpty(_ name: String, type: Int, at path: [String], line: UInt = #line,
                                         _ event: (Any) -> [String: Any]) throws {
        XCTAssertTrue(try exported(name, type: type, event(NSNull()), at: path) is NSNull, "null", line: line)
        XCTAssertEqual(try exported(name, type: type, event(""), at: path) as? String, "", "\"\"", line: line)
    }
    
    /// `xp_malware_remediated.remediated_path`.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export has no such event.
    func testRemediatedPathRoundTrip() throws {
        try assertKeepsNullAndEmpty("xp_malware_remediated", type: 113, at: ["remediated_path"]) {
            ["signature_version": "1", "malware_identifier": "Example", "incident_identifier": "0",
             "action_type": "path", "success": true, "result_description": "", "remediated_path": $0,
             "remediated_process_audit_token": NSNull()]
        }
    }
    
    /// `btm_launch_item_add.executable_path` and `btm_launch_item_add.item.app_url`.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export has no such event.
    func testLaunchItemRoundTrip() throws {
        func item(appURL: Any) -> [String: Any] {
            ["item_type": 2, "legacy": false, "managed": false, "uid": 0, "app_url": appURL,
             "item_url": "file:///Library/LaunchDaemons/com.example.agent.plist"]
        }
        try assertKeepsNullAndEmpty("btm_launch_item_add", type: 124, at: ["executable_path"]) {
            ["instigator": NSNull(), "app": NSNull(), "item": item(appURL: NSNull()), "executable_path": $0]
        }
        try assertKeepsNullAndEmpty("btm_launch_item_add", type: 124, at: ["item", "app_url"]) {
            ["instigator": NSNull(), "app": NSNull(), "item": item(appURL: $0), "executable_path": NSNull()]
        }
    }
    
    /// `login_login.failure_message`.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export has no such event.
    func testLoginFailureMessageRoundTrip() throws {
        try assertKeepsNullAndEmpty("login_login", type: 122, at: ["failure_message"]) {
            ["success": false, "failure_message": $0, "username": "testuser", "uid": NSNull()]
        }
    }
    
    /// `od_create_user.db_path`.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export has no such event.
    func testOpenDirectoryDatabasePathRoundTrip() throws {
        try assertKeepsNullAndEmpty("od_create_user", type: 141, at: ["db_path"]) {
            ["instigator": NSNull(), "error_code": 0, "user_name": "testuser", "node_name": "/Local/Default",
             "db_path": $0]
        }
    }
    
    /// `gatekeeper_user_override.signing_info.team_id`.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export has no such event.
    func testGatekeeperTeamIDRoundTrip() throws {
        try assertKeepsNullAndEmpty("gatekeeper_user_override", type: 146, at: ["signing_info", "team_id"]) {
            ["file_type": 0, "file": "/Applications/Example.app", "sha256": NSNull(),
             "signing_info": ["cdhash": String(repeating: "0", count: 40), "signing_id": "com.example.app",
                              "team_id": $0]]
        }
    }
    
    /// `process.team_id`.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export isn't a JSON object.
    func testProcessTeamIDRoundTrip() throws {
        for value in [NSNull(), "" as Any] {
            var record = try fixtureObject("eslogger-exit.jsonl")
            var process = try XCTUnwrap(record["process"] as? [String: Any])
            process["team_id"] = value
            record["process"] = process
            let exported = (try export(try importRecord(record))["process"] as? [String: Any])?["team_id"]
            XCTAssertEqual(exported as? NSObject, value as? NSObject)
        }
    }
}
