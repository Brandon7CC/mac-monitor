//
//  MuteAccessTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Who may change the saved mute set
/// Pins who may change the saved mute set from Mac Monitor: only an administrator, and only while it owns the event
/// stream or nobody does. Everyone else may list it, and each refusal has its own status and sentence.
final class MuteAccessTests: XCTestCase {
    /// An administrator's Mac Monitor may change the set while it controls the stream, and only list it otherwise. A
    /// standard user's may only ever list it.
    func testAppAccess() {
        XCTAssertEqual(MuteAccess.app(isAdministrator: true, controlsStream: true), .write)
        XCTAssertEqual(MuteAccess.app(isAdministrator: true, controlsStream: false), .read)
        XCTAssertEqual(MuteAccess.app(isAdministrator: false, controlsStream: true), .standardUser)
        XCTAssertEqual(MuteAccess.app(isAdministrator: false, controlsStream: false), .standardUser)
    }
    
    /// Each read-only access refuses with its own status and says why. Write refuses nothing.
    func testRefusals() {
        XCTAssertNil(MuteAccess.write.refusal)
        XCTAssertEqual(MuteAccess.read.refusal?.status, .refused)
        XCTAssertTrue(MuteAccess.read.refusal?.problem.contains("owns the event stream") == true)
        XCTAssertEqual(MuteAccess.standardUser.refusal?.status, .notAdministrator)
        XCTAssertEqual(MuteAccess.standardUser.refusal?.problem, """
            Only an administrator can change the saved mute set. You can still view it, export it, and record with it.
            """)
    }
    
    /// A connection is vouched for by its effective user alone, and no connection by no one, whatever the check
    /// says: the gate a Mac Monitor connection's request about the saved set passes.
    func testAConnectionsEffectiveUserDecides() {
        let administrators = AdministratorCheck { $0 == 501 }
        XCTAssertTrue(administrators.isAdministrator(FakePeer(euid: 501)))
        XCTAssertFalse(administrators.isAdministrator(FakePeer(euid: 502)))
        XCTAssertFalse(AdministratorCheck { _ in true }.isAdministrator(nil))
        XCTAssertTrue(AdministratorCheck.openDirectory.isAdministrator(FakePeer(euid: 0)))
        
    }
    
    /// A connection controls the event stream when it owns it, or when nobody does. A connection that isn't the
    /// owner, or no connection at all, doesn't while someone does.
    func testOnlyTheStreamsOwnerControlsIt() {
        let owner = FakePeer(euid: 501), other = FakePeer(euid: 501)
        XCTAssertTrue(MuteAccess.controlsStream(owner, owner: owner))
        XCTAssertTrue(MuteAccess.controlsStream(other, owner: nil))
        XCTAssertTrue(MuteAccess.controlsStream(nil, owner: nil))
        XCTAssertFalse(MuteAccess.controlsStream(other, owner: owner), "Same user, another connection")
        XCTAssertFalse(MuteAccess.controlsStream(nil, owner: owner))
        
        let administrators = AdministratorCheck { $0 == 501 }
        let access = { (caller: FakePeer?, owner: FakePeer?) in
            MuteAccess.app(isAdministrator: administrators.isAdministrator(caller),
                           controlsStream: MuteAccess.controlsStream(caller, owner: owner))
        }
        XCTAssertEqual(access(owner, owner), .write)
        XCTAssertEqual(access(other, owner), .read)
        XCTAssertEqual(access(FakePeer(euid: 502), nil), .standardUser)
        XCTAssertEqual(access(nil, nil), .standardUser)
    }
    
    /// Open Directory counts root, a member of `admin` on every Mac, and never `nobody` or a user ID with no account.
    func testOpenDirectoryAnswers() {
        XCTAssertTrue(AdministratorCheck.openDirectory.isAdministrator(0))
        XCTAssertFalse(AdministratorCheck.openDirectory.isAdministrator(uid_t(bitPattern: -2)))
        XCTAssertFalse(AdministratorCheck.openDirectory.isAdministrator(3_999_999))
        XCTAssertFalse(AdministratorCheck.isMember(0, of: 3_999_999))
    }
}
