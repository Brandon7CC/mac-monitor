//
//  CaptureCrashGuardTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Crash guards
/// Pins that the Security Extension records events whose values it used to trap on: a user this Mac doesn't know,
/// union types a newer macOS adds, and code signing flags with bit 31 set; and that an authorization event keeps the
/// processes and tokens Endpoint Security gives. Open Directory events without their instigator are pinned in
/// ``OpenDirectoryCaptureTests``.
final class CaptureCrashGuardTests: XCTestCase {
    // MARK: Login
    
    /// A login by a user ID this Mac has no account for keeps an empty user name.
    func testLoginByUnknownUser() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN)
        var login = es_event_login_login_t()
        login.success = true
        login.username = fixture.token("testuser")
        login.has_uid = true
        login.uid.uid = 0x7FFF_FFF0
        fixture.message.pointee.event.login_login = fixture.pointer(login)
        let event = LoginLoginEvent(from: fixture.raw)
        XCTAssertEqual(event.uid, 0x7FFF_FFF0)
        XCTAssertEqual(event.uid_human, "")
    }
    
    /// A login by a user this Mac knows is named, whatever the user's ID.
    func testLoginByKnownUser() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN)
        var login = es_event_login_login_t()
        login.success = true
        login.username = fixture.token("root")
        login.has_uid = true
        login.uid.uid = 0
        fixture.message.pointee.event.login_login = fixture.pointer(login)
        XCTAssertEqual(LoginLoginEvent(from: fixture.raw).uid_human, "root")
    }
    
    // MARK: Code signing
    
    /// Code signing flags with bit 31 set have no `Int32`: they're read by bit pattern.
    func testCodeSigningFlagsWithBit31() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
        let valid = fixture.process(path: "/nonexistent/Example", flags: 0x8000_0001, platform: false)
        XCTAssertEqual(ProcessHelpers.codeSigningType(for: valid.pointee), .unknown)
        let invalid = fixture.process(path: "/nonexistent/Example", flags: 0x8000_0000, platform: false)
        XCTAssertEqual(ProcessHelpers.codeSigningType(for: invalid.pointee), .unsigned)
        XCTAssertEqual(Process(from: valid.pointee, version: 10).codesigning_flags, 0x8000_0001)
    }
    
    // MARK: Unions
    
    /// A Gatekeeper override whose `file_type` names neither arm of its union is recorded and exported without one.
    ///
    /// - Throws: An `XCTest` failure if the export has no Gatekeeper event.
    func testGatekeeperUnknownFileType() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE)
        let override = fixture.allocate(es_event_gatekeeper_user_override_t.self)
        override.pointee.file_type = es_gatekeeper_user_override_file_type_t(rawValue: 7)
        fixture.message.pointee.event.gatekeeper_user_override = override
        XCTAssertEqual(FilePathUnion.from(override: override.pointee), .unknown)
        
        let message = Message(from: fixture.raw)
        XCTAssertEqual(message.target_path, "")
        let gatekeeper = try event("gatekeeper_user_override", in: try export(message))
        XCTAssertEqual(gatekeeper["file_type"] as? Int, 7)
        XCTAssertNil(gatekeeper["file"])
        XCTAssertNil(gatekeeper["file_path"])
    }
    
    /// A create event whose `destination_type` names neither arm of its union is recorded, and its file has no name.
    ///
    /// - Throws: An `XCTest` failure if the export has no create event.
    func testCreateWithUnknownDestinationType() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CREATE)
        fixture.message.pointee.event.create.destination_type = es_destination_type_t(rawValue: 9)
        XCTAssertEqual(FileDestination.from(create: fixture.message.pointee.event.create), .unknown)
        
        let message = Message(from: fixture.raw)
        guard case .create(let create) = message.event else { return XCTFail("Expected a create event") }
        XCTAssertEqual(create.destination, .unknown)
        XCTAssertEqual(message.target_path, "")
        XCTAssertEqual(withStoredEvent(message) { [$0.event.create?.targetPath, $0.event.create?.fileName] }, ["", ""])
        let destination = try event("create", in: try export(message))["destination"] as? [String: Any]
        XCTAssertEqual(destination?.count, 0)
    }
    
    /// A rename event whose `destination_type` names neither arm of its union is recorded without a destination path.
    func testRenameWithUnknownDestinationType() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_RENAME)
        fixture.message.pointee.event.rename.source = fixture.file("/private/tmp/example/a.txt")
        fixture.message.pointee.event.rename.destination_type = es_destination_type_t(rawValue: 9)
        let rename = FileRenameEvent(from: fixture.raw)
        XCTAssertEqual(rename.destination, .unknown)
        XCTAssertEqual(rename.destination_path, "")
        XCTAssertEqual(EventType.rename(rename).summary(initiatingPath: "/usr/bin/true").context, "a.txt → ")
    }
    
    /// A created file's path joins its directory and its file name, and its name is read as a path, spaces and all.
    func testCreatedFileName() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CREATE)
        fixture.message.pointee.event.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        fixture.message.pointee.event.create.destination.new_path.dir = fixture.file("/private/tmp/example")
        fixture.message.pointee.event.create.destination.new_path.filename = fixture.token("Quarterly Report.txt")
        let names = withStoredEvent(Message(from: fixture.raw)) {
            [$0.event.create?.targetPath, $0.event.create?.fileName]
        }
        XCTAssertEqual(names, ["/private/tmp/example/Quarterly Report.txt", "Quarterly Report.txt"])
    }
    
    /// A trace's create event with an empty destination reads as one that can't be read, rather than being skipped.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no create event.
    func testImportedCreateWithEmptyDestination() throws {
        let record = try esloggerRecord("create", type: 13, ["destination_type": 9, "destination": [:]])
        let message = try importRecord(record)
        guard case .create(let create) = message.event else { return XCTFail("Expected a create event") }
        XCTAssertEqual(create.destination, .unknown)
        XCTAssertEqual((try event("create", in: try export(message))["destination"] as? [String: Any])?.count, 0)
    }
    
    // MARK: Fields of a newer message version
    
    /// A signal's `instigator` is read from message version 9: before it, its bytes are reserved.
    func testSignalInstigatorBeforeVersion9() {
        for (version, expected) in [(UInt32(8), nil), (9, "/usr/bin/kill")] {
            let fixture = rawMessage(version: version, type: ES_EVENT_TYPE_NOTIFY_SIGNAL)
            fixture.message.pointee.event.signal.sig = SIGTERM
            fixture.message.pointee.event.signal.target = fixture.process(path: "/usr/bin/false")
            fixture.message.pointee.event.signal.instigator = fixture.process(path: "/usr/bin/kill")
            let signal = ProcessSignalEvent(from: fixture.raw)
            XCTAssertEqual(signal.instigator?.executable?.path, expected, "version \(version)")
        }
    }
    
    /// A mount's `disposition` is read from message version 8: before it, its zeros would read as an external device.
    func testMountDispositionBeforeVersion8() {
        for (version, expected) in [(UInt32(7), ES_MOUNT_DISPOSITION_UNKNOWN), (8, ES_MOUNT_DISPOSITION_INTERNAL)] {
            let fixture = rawMessage(version: version, type: ES_EVENT_TYPE_NOTIFY_MOUNT)
            fixture.message.pointee.event.mount.statfs = fixture.allocate(Darwin.statfs.self)
            fixture.message.pointee.event.mount.disposition = ES_MOUNT_DISPOSITION_INTERNAL
            XCTAssertEqual(MountEvent(from: fixture.raw).disposition, Int16(expected.rawValue), "version \(version)")
        }
    }
    
    // MARK: Authorization
    
    /// Record an authorization event, and export it.
    ///
    /// - Parameters:
    ///   - slot: The event's place in the message's `event` union.
    ///   - type: The event's type.
    ///   - version: The message's version.
    ///   - processes: Give the event an instigator (pid 33) and a petitioner (pid 44), or leave both `NULL`. Their
    ///     tokens are always set.
    /// - Returns: The exported event.
    /// - Throws: An `XCTest` failure if the export has no such event.
    private func exportAuthorization<Event: SettableAuthorizationEvent>(
        _ slot: WritableKeyPath<es_events_t, UnsafeMutablePointer<Event>>, type: es_event_type_t, version: UInt32,
        processes: Bool) throws -> [String: Any] {
        let fixture = rawMessage(version: version, type: type)
        let event = fixture.allocate(Event.self)
        if processes {
            event.pointee.instigator = fixture.process(path: "/usr/bin/security", pid: 33)
            event.pointee.petitioner = fixture.process(path: "/usr/bin/security", pid: 44)
        }
        event.pointee.instigator_token = RawMessageFixture.auditToken(pid: 33)
        event.pointee.petitioner_token = RawMessageFixture.auditToken(pid: 44)
        fixture.message.pointee.event[keyPath: slot] = event
        let name = String(eventTypeToString(from: type).dropFirst("ES_EVENT_TYPE_NOTIFY_".count)).lowercased()
        return try self.event(name, in: try export(Message(from: fixture.raw)))
    }
    
    /// The pid of each process or audit token of an exported event.
    ///
    /// - Parameters:
    ///   - event: The exported event.
    ///   - keys: The processes' or tokens' keys.
    /// - Returns: Each one's pid, or `nil` where it's `null`.
    private static func pids(_ event: [String: Any], _ keys: String...) -> [Int?] {
        keys.map { key in
            let object = event[key] as? [String: Any]
            return ((object?["audit_token"] as? [String: Any]) ?? object)?["pid"] as? Int
        }
    }
    
    /// An authorization event keeps each process and token Endpoint Security gives, apart: a process left out
    /// (`NULL`) keeps its token, and before message version 8 a process is kept without one.
    ///
    /// - Throws: An `XCTest` failure if an export has no such event.
    func testAuthorizationProcessesAndTokens() throws {
        for version: UInt32 in [7, 8] {
            for processes in [true, false] {
                let events = [
                    try exportAuthorization(\.authorization_petition, type: ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION,
                                            version: version, processes: processes),
                    try exportAuthorization(\.authorization_judgement,
                                            type: ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT, version: version,
                                            processes: processes),
                ]
                for event in events {
                    let label = "version \(version), \(processes ? "with" : "without") processes"
                    XCTAssertEqual(Self.pids(event, "instigator", "petitioner"), processes ? [33, 44] : [nil, nil],
                                   label)
                    XCTAssertEqual(Self.pids(event, "instigator_token", "petitioner_token"),
                                   version >= 8 ? [33, 44] : [nil, nil], label)
                }
            }
        }
    }
    
    // MARK: Fixed-size strings
    
    /// A `statfs` name the kernel left without a NUL is read to the end of its array and no further.
    func testStatFSNameWithoutNUL() {
        var raw = Darwin.statfs()
        withUnsafeMutableBytes(of: &raw.f_mntonname) { _ = $0.initializeMemory(as: UInt8.self, repeating: 0x61) }
        withUnsafeMutableBytes(of: &raw.f_fstypename) { $0.copyBytes(from: Array("apfs\0".utf8)) }
        let stat = StatFS(from: raw)
        XCTAssertEqual(stat.f_mntonname, String(repeating: "a", count: Int(MAXPATHLEN)))
        XCTAssertEqual(stat.f_fstypename, "apfs")
    }
}


// MARK: - Authorization test support
/// An `es_event_authorization_petition_t` or `es_event_authorization_judgement_t`, whose processes a test can set.
private protocol SettableAuthorizationEvent {
    var instigator: UnsafeMutablePointer<es_process_t>? { get set }
    var petitioner: UnsafeMutablePointer<es_process_t>? { get set }
    var instigator_token: audit_token_t { get set }
    var petitioner_token: audit_token_t { get set }
}

extension es_event_authorization_petition_t: SettableAuthorizationEvent {}
extension es_event_authorization_judgement_t: SettableAuthorizationEvent {}
