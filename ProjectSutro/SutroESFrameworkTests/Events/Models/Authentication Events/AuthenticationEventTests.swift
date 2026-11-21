//
//  AuthenticationEventTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/21/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Authentication events
/// Pins `ES_EVENT_TYPE_NOTIFY_AUTHENTICATION`: each arm of its `data` as Endpoint Security gives it, what Mac Monitor
/// derives, how the event tables summarize it, the record as eslogger nests it, and eslogger's own record read back.
final class AuthenticationEventTests: XCTestCase {
    /// An authentication's message, with the arm its type names.
    ///
    /// - Parameters:
    ///   - type: The kind of authentication.
    ///   - success: Did it succeed?
    ///   - version: The message's version.
    ///   - fill: Sets the arm in the event's union.
    /// - Returns: The event as Mac Monitor models it.
    private func message(_ type: es_authentication_type_t, success: Bool = true, version: UInt32 = 10,
                         _ fill: (RawMessageFixture, UnsafeMutablePointer<es_event_authentication_t>) -> Void)
        -> Message {
        let fixture = rawMessage(version: version, type: ES_EVENT_TYPE_NOTIFY_AUTHENTICATION)
        let event = fixture.allocate(es_event_authentication_t.self)
        event.pointee.success = success
        event.pointee.type = type
        fill(fixture, event)
        fixture.message.pointee.event.authentication = event
        return Message(from: fixture.raw)
    }

    /// An Open Directory authentication.
    ///
    /// - Parameters:
    ///   - success: Did it succeed?
    ///   - version: The message's version.
    ///   - instigator: Give it an instigator (dscl, pid 33), or leave it `NULL`. Its token is always set.
    ///   - database: The node's database, or `nil` for none.
    /// - Returns: The event.
    private func openDirectory(success: Bool = false, version: UInt32 = 10, instigator: Bool = true,
                               database: String? = "/var/db/dslocal/nodes/Default") -> Message {
        message(ES_AUTHENTICATION_TYPE_OD, success: success, version: version) { fixture, event in
            let arm = fixture.allocate(es_event_authentication_od_t.self)
            if instigator {
                arm.pointee.instigator = fixture.process(path: "/usr/bin/dscl", signingID: "com.apple.dscl", pid: 33)
            }
            arm.pointee.record_type = fixture.token("Users")
            arm.pointee.record_name = fixture.token("user")
            arm.pointee.node_name = fixture.token("/Local/Default")
            arm.pointee.db_path = fixture.token(database)
            arm.pointee.instigator_token = RawMessageFixture.auditToken(pid: 33)
            event.pointee.data.od = arm
        }
    }

    /// An Open Directory authentication keeps its record, node, database and instigator, names its type, and is
    /// summarized by its result, its kind and its record, with the instigator as its target.
    func testOpenDirectory() throws {
        let message = openDirectory()
        let event = try XCTUnwrap(message.event.authentication)
        XCTAssertFalse(event.success)
        XCTAssertEqual(event.type, 0)
        XCTAssertEqual(event.type_string, "ES_AUTHENTICATION_TYPE_OD")
        let arm = try XCTUnwrap(event.data.od)
        XCTAssertEqual([arm.record_type, arm.record_name, arm.node_name], ["Users", "user", "/Local/Default"])
        XCTAssertEqual(arm.db_path, "/var/db/dslocal/nodes/Default")
        XCTAssertEqual(arm.instigator?.executable?.path, "/usr/bin/dscl")
        XCTAssertEqual(arm.instigator_token?.pid, 33)
        XCTAssertEqual(event.account, "user")
        XCTAssertEqual(message.context, "[Fail] OD → user")
        XCTAssertEqual(message.target_path, "/usr/bin/dscl")
        XCTAssertEqual(openDirectory(success: true).context, "[Success] OD → user")
    }

    /// The instigator and its token are kept apart: a `NULL` instigator keeps its token, a node that isn't local has
    /// no database, and before message version 8 there's no token to read.
    func testInstigatorTokenAndDatabase() throws {
        let unnamed = try XCTUnwrap(openDirectory(instigator: false, database: nil).event.authentication)
        XCTAssertNil(unnamed.instigator)
        XCTAssertEqual(unnamed.instigator_token?.pid, 33)
        XCTAssertNil(unnamed.data.od?.db_path)
        let older = try XCTUnwrap(openDirectory(version: 7).event.authentication)
        XCTAssertEqual(older.instigator?.executable?.name, "dscl")
        XCTAssertNil(older.instigator_token)
    }

    /// Touch ID keeps its mode and the user it verified, and names no user when it has none.
    func testTouchID() throws {
        for (hasUID, mode) in [(true, ES_TOUCHID_MODE_VERIFICATION), (false, ES_TOUCHID_MODE_IDENTIFICATION)] {
            let message = message(ES_AUTHENTICATION_TYPE_TOUCHID) { fixture, event in
                let arm = fixture.allocate(es_event_authentication_touchid_t.self)
                arm.pointee.instigator = fixture.process(path: "/usr/libexec/coreauthd", pid: 44)
                arm.pointee.touchid_mode = mode
                arm.pointee.has_uid = hasUID
                arm.pointee.uid.uid = 0
                arm.pointee.instigator_token = RawMessageFixture.auditToken(pid: 44)
                event.pointee.data.touchid = arm
            }
            let event = try XCTUnwrap(message.event.authentication)
            let arm = try XCTUnwrap(event.data.touchid)
            XCTAssertEqual(event.type_string, "ES_AUTHENTICATION_TYPE_TOUCHID")
            XCTAssertEqual(arm.touchid_mode_string, hasUID ? "ES_TOUCHID_MODE_VERIFICATION"
                                                           : "ES_TOUCHID_MODE_IDENTIFICATION")
            XCTAssertEqual(arm.uid, hasUID ? 0 : nil)
            XCTAssertEqual(arm.uid_human, hasUID ? "root" : nil)
            XCTAssertEqual(message.context, hasUID ? "[Success] TOUCHID → root" : "[Success] TOUCHID → ")
            XCTAssertEqual(message.target_path, "/usr/libexec/coreauthd")
        }
    }

    /// A token keeps its identifier and key hash, and its Kerberos principal only when it has one.
    func testToken() throws {
        for principal in [String?.none, "user@EXAMPLE.COM"] {
            let message = message(ES_AUTHENTICATION_TYPE_TOKEN) { fixture, event in
                let arm = fixture.allocate(es_event_authentication_token_t.self)
                arm.pointee.pubkey_hash = fixture.token("0A1B2C")
                arm.pointee.token_id = fixture.token("com.apple.pivtoken:0001")
                arm.pointee.kerberos_principal = fixture.token(principal)
                arm.pointee.instigator_token = RawMessageFixture.auditToken(pid: 55)
                event.pointee.data.token = arm
            }
            let event = try XCTUnwrap(message.event.authentication)
            let arm = try XCTUnwrap(event.data.token)
            XCTAssertEqual([arm.pubkey_hash, arm.token_id], ["0A1B2C", "com.apple.pivtoken:0001"])
            XCTAssertEqual(arm.kerberos_principal, principal)
            XCTAssertNil(arm.instigator)
            XCTAssertEqual(event.instigator_token?.pid, 55)
            XCTAssertEqual(message.context, "[Success] TOKEN → \(principal ?? "")")
            XCTAssertNil(message.target_path)
        }
    }

    /// Auto Unlock keeps its user and names its purpose. It has no instigator.
    func testAutoUnlock() throws {
        let message = message(ES_AUTHENTICATION_TYPE_AUTO_UNLOCK) { fixture, event in
            let arm = fixture.allocate(es_event_authentication_auto_unlock_t.self)
            arm.pointee.username = fixture.token("user")
            arm.pointee.type = ES_AUTO_UNLOCK_AUTH_PROMPT
            event.pointee.data.auto_unlock = arm
        }
        let event = try XCTUnwrap(message.event.authentication)
        let arm = try XCTUnwrap(event.data.auto_unlock)
        XCTAssertEqual(arm.username, "user")
        XCTAssertEqual(arm.type, 2)
        XCTAssertEqual(arm.type_string, "ES_AUTO_UNLOCK_AUTH_PROMPT")
        XCTAssertNil(event.instigator)
        XCTAssertNil(event.instigator_token)
        XCTAssertEqual(message.context, "[Success] AUTO_UNLOCK → user")
    }

    /// A type a newer macOS adds is recorded without an arm, and exported with empty data.
    func testUnknownType() throws {
        let message = message(es_authentication_type_t(rawValue: 9)) { _, _ in }
        let event = try XCTUnwrap(message.event.authentication)
        XCTAssertEqual(event.data, .unknown)
        XCTAssertEqual(event.type_string, "UNKNOWN")
        XCTAssertNil(event.account)
        let exported = try self.event("authentication", in: try export(message))
        XCTAssertEqual(exported["type"] as? Int, 9)
        XCTAssertEqual((exported["data"] as? [String: Any])?.count, 0)
    }

    /// The record nests the arm under `data` by its name, as eslogger does, with `null` for what Endpoint Security
    /// left out, and holds no other arm.
    func testRecordNestsTheArm() throws {
        let exported = try event("authentication", in: try export(openDirectory(instigator: false, database: nil)))
        XCTAssertEqual(Set(exported.keys), ["success", "type", "type_string", "data"])
        XCTAssertEqual(exported["success"] as? Bool, false)
        let data = try XCTUnwrap(exported["data"] as? [String: Any])
        XCTAssertEqual(Array(data.keys), ["od"])
        let arm = try XCTUnwrap(data["od"] as? [String: Any])
        XCTAssertEqual(Set(arm.keys), ["instigator", "record_type", "record_name", "node_name", "db_path",
                                       "instigator_token"])
        XCTAssertTrue(arm["instigator"] is NSNull)
        XCTAssertTrue(arm["db_path"] is NSNull)
        XCTAssertEqual((arm["instigator_token"] as? [String: Any])?["pid"] as? Int, 33)
        let named = try event("authentication", in: try export(openDirectory()))
        let instigator = ((named["data"] as? [String: Any])?["od"] as? [String: Any])?["instigator"] as? [String: Any]
        XCTAssertEqual((instigator?["executable"] as? [String: Any])?["path"] as? String, "/usr/bin/dscl")
    }

    /// eslogger's own record of a failed `dscl -authonly`, recorded on macOS 27.2, opens as the event it was, gains
    /// Mac Monitor's names, and exports with eslogger's values where eslogger had them.
    func testEsloggerRecordOpens() throws {
        let message = try XCTUnwrap(try fixtureMessages("eslogger-authentication.jsonl").first)
        XCTAssertEqual(message.es_event_type, "ES_EVENT_TYPE_NOTIFY_AUTHENTICATION")
        let event = try XCTUnwrap(message.event.authentication)
        XCTAssertFalse(event.success)
        XCTAssertEqual(event.type_string, "ES_AUTHENTICATION_TYPE_OD")
        XCTAssertEqual(event.data.od?.record_name, "user")
        XCTAssertEqual(event.data.od?.node_name, "/Local/Default")
        XCTAssertEqual(event.instigator?.executable?.path, "/usr/bin/dscl")
        XCTAssertEqual(event.instigator?.signing_id, "com.apple.dscl")
        XCTAssertEqual(message.context, "[Fail] OD → user")
        let exported = try self.event("authentication", in: try export(message))
        let arm = try XCTUnwrap((exported["data"] as? [String: Any])?["od"] as? [String: Any])
        XCTAssertEqual(arm["db_path"] as? String, "/var/db/dslocal/nodes/Default")
        XCTAssertEqual(arm["record_type"] as? String, "Users")
        XCTAssertEqual((arm["instigator_token"] as? [String: Any])?["pid"] as? Int,
                       event.instigator_token.map { Int($0.pid) })
    }

    /// An indicator reads the event's fields in the Security Extension, the instigator's included.
    func testAnIndicatorReadsTheEvent() throws {
        let source = #"event.authentication != nil AND event.authentication.success == NO AND "#
            + #"event.authentication.data.od.instigator.signing_id == "com.apple.dscl""#
        let indicator = Indicator(name: "Password check failed", description: "", symbol: "star", color: .blue,
                                  predicate: source)
        XCTAssertNil(indicator.sensorProblem)
        let compiled = CompiledIndicators([indicator])
        var values = MessageValueCache()
        XCTAssertEqual(compiled.evaluate(openDirectory(), values: &values).hits.map(\.id), [indicator.id])
        var others = MessageValueCache()
        XCTAssertEqual(compiled.evaluate(openDirectory(success: true), values: &others).hits.map(\.id), [])
    }
}
