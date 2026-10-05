//
//  UnsignedValueTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Unsigned values
/// Pins that unsigned Endpoint Security values too large for Mac Monitor's signed types are kept by bit pattern (the
/// Security Extension used to trap on them) and exported unsigned, as eslogger writes them.
final class UnsignedValueTests: XCTestCase {
    /// `nobody`'s user ID, which has no `Int32`.
    private static let nobody: UInt32 = 4_294_967_294
    
    /// An OpenSSH logout by a user ID of 2^31 or more.
    ///
    /// - Throws: An `XCTest` failure if the export isn't a JSON object.
    func testOpenSSHLogoutUID() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT)
        var logout = es_event_openssh_logout_t()
        logout.username = fixture.token("testuser")
        logout.source_address = fixture.token("192.0.2.1")
        logout.uid = Self.nobody
        fixture.message.pointee.event.openssh_logout = fixture.pointer(logout)
        XCTAssertEqual(SSHLogoutEvent(from: fixture.raw).uid, -2)
        XCTAssertTrue(exportText(Message(from: fixture.raw)).contains(#""uid":4294967294"#))
    }
    
    /// An OpenSSH login by a user ID of 2^31 or more.
    func testOpenSSHLoginUID() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN)
        var login = es_event_openssh_login_t()
        login.success = true
        login.has_uid = true
        login.uid.uid = Self.nobody
        fixture.message.pointee.event.openssh_login = fixture.pointer(login)
        XCTAssertEqual(SSHLoginEvent(from: fixture.raw).uid, -2)
        XCTAssertTrue(exportText(Message(from: fixture.raw)).contains(#""uid":4294967294"#))
    }
    
    /// eslogger's unsigned user ID reads back and exports as it was written.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no such event.
    func testImportedOpenSSHLogoutUID() throws {
        let record = try esloggerRecord("openssh_logout", type: 121, [
            "source_address_type": 1, "source_address": "192.0.2.1", "username": "testuser", "uid": Self.nobody,
        ])
        let logout = try event("openssh_logout", in: try export(try importRecord(record)))
        XCTAssertEqual(logout["uid"] as? UInt32, Self.nobody)
    }
    
    /// Login window session IDs are `uint32_t`.
    func testLoginWindowSessionID() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN)
        var login = es_event_lw_session_login_t()
        login.username = fixture.token("testuser")
        login.graphical_session_id = 4_294_967_280
        fixture.message.pointee.event.lw_session_login = fixture.pointer(login)
        XCTAssertEqual(LWLoginEvent(from: fixture.raw).graphical_session_id, -16)
        XCTAssertTrue(exportText(Message(from: fixture.raw)).contains(#""graphical_session_id":4294967280"#))
        
        fixture.message.pointee.event_type = ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK
        var unlock = es_event_lw_session_unlock_t()
        unlock.username = fixture.token("testuser")
        unlock.graphical_session_id = 4_294_967_280
        fixture.message.pointee.event.lw_session_unlock = fixture.pointer(unlock)
        XCTAssertEqual(LWUnlockEvent(from: fixture.raw).graphical_session_id, -16)
        XCTAssertTrue(exportText(Message(from: fixture.raw)).contains(#""graphical_session_id":4294967280"#))
    }
    
    /// IOKit registry IDs are `uint64_t`.
    func testIOKitParentRegistryID() {
        let fixture = rawMessage(version: 10, type: ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN)
        fixture.message.pointee.event.iokit_open.user_client_class = fixture.token("IOHIDLibUserClient")
        fixture.message.pointee.event.iokit_open.parent_registry_id = 0x8000_0000_0000_0001
        fixture.message.pointee.event.iokit_open.parent_path = fixture.token("IOService:/AppleARMPE/example")
        XCTAssertEqual(IOKitOpenEvent(from: fixture.raw).parent_registry_id, Int64(bitPattern: 0x8000_0000_0000_0001))
        XCTAssertTrue(exportText(Message(from: fixture.raw)).contains(#""parent_registry_id":9223372036854775809"#))
    }
    
    /// `mprotect`'s address and size are 64-bit unsigned.
    func testMProtectAddress() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_MPROTECT)
        fixture.message.pointee.event.mprotect.address = 0xFFFF_FFFF_FFFF_F000
        fixture.message.pointee.event.mprotect.size = 0x8000_0000_0000_0000
        let mprotect = MProtectEvent(from: fixture.raw)
        XCTAssertEqual(mprotect.address, -4_096)
        XCTAssertEqual(mprotect.hex_address, "0xfffffffffffff000")
        let text = exportText(Message(from: fixture.raw))
        XCTAssertTrue(text.contains(#""address":18446744073709547520"#), text)
        XCTAssertTrue(text.contains(#""size":9223372036854775808"#), text)
    }
    
    /// `mprotect`'s address in hex is the address's own digits.
    func testMProtectHexAddress() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_MPROTECT)
        fixture.message.pointee.event.mprotect.address = 0x1_04B9_C000
        XCTAssertEqual(MProtectEvent(from: fixture.raw).hex_address, "0x104b9c000")
    }
    
    /// Mac Monitor 2.1 wrote a pointer as `hex_address`: it's derived again from the address when stored.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no `mprotect` event.
    func testMacMonitor21MProtectHexAddress() throws {
        let record = try legacyRecord("mprotect", type: ES_EVENT_TYPE_NOTIFY_MPROTECT, [
            "protection": 1, "address": 4_374_282_240, "size": 16_384, "hex_address": "0x7542c64030", "kb_size": 16,
            "flags": ["VM_PROT_READ"],
        ])
        let message = try importRecord(record)
        XCTAssertEqual(message.event.mprotect?.hex_address, "0x7542c64030")
        let mprotect = try event("mprotect", in: try export(message))
        XCTAssertEqual(mprotect["hex_address"] as? String, "0x104ba4000")
    }
    
    /// Pipe IDs are `uint64_t`.
    func testPipeID() {
        var fd = es_fd_t()
        fd.fdtype = UInt32(PROX_FDTYPE_PIPE)
        fd.pipe.pipe_id = UInt64.max
        XCTAssertEqual(FDPipe(from: fd).pipe_id, -1)
    }
}
