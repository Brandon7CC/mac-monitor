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
    /// A connection from one effective user, as the Security Extension reads it.
    private final class Peer: PeerConnection {
        let effectiveUserIdentifier: uid_t
        
        /// - Parameter euid: The peer's effective user ID.
        init(euid: uid_t) {
            effectiveUserIdentifier = euid
        }
        
        /// Unused: deciding access pins no requirement.
        ///
        /// - Parameter requirement: The requirement string.
        func setCodeSigningRequirement(_ requirement: String) {}
    }
    
    /// An administrator's Mac Monitor may change the set while it controls the stream, and only list it otherwise; a
    /// standard user's may only ever list it.
    func testAppAccess() {
        XCTAssertEqual(MuteAccess.app(isAdministrator: true, controlsStream: true), .write)
        XCTAssertEqual(MuteAccess.app(isAdministrator: true, controlsStream: false), .read)
        XCTAssertEqual(MuteAccess.app(isAdministrator: false, controlsStream: true), .standardUser)
        XCTAssertEqual(MuteAccess.app(isAdministrator: false, controlsStream: false), .standardUser)
    }
    
    /// Each read-only access refuses with its own status and says why; write refuses nothing.
    func testRefusals() {
        XCTAssertNil(MuteAccess.write.refusal)
        XCTAssertEqual(MuteAccess.read.refusal?.status, .refused)
        XCTAssertTrue(MuteAccess.read.refusal?.problem.contains("owns the event stream") == true)
        XCTAssertEqual(MuteAccess.standardUser.refusal?.status, .notAdministrator)
        XCTAssertEqual(MuteAccess.standardUser.refusal?.problem, """
            Only an administrator can change the saved mute set. You can still view it, export it, and record with it.
            """)
    }
    
    /// A check passed in decides alone, so tests need no real accounts.
    func testAnInjectedCheckDecides() {
        let administrators = AdministratorCheck { $0 == 501 }
        XCTAssertTrue(administrators.isAdministrator(501))
        XCTAssertFalse(administrators.isAdministrator(502))
    }
    
    /// A connection is vouched for by its effective user alone, and no connection by no one, whatever the check
    /// says: the gate a Mac Monitor connection's request about the saved set passes.
    func testAConnectionsEffectiveUserDecides() {
        let administrators = AdministratorCheck { $0 == 501 }
        XCTAssertTrue(administrators.isAdministrator(Peer(euid: 501)))
        XCTAssertFalse(administrators.isAdministrator(Peer(euid: 502)))
        XCTAssertFalse(AdministratorCheck { _ in true }.isAdministrator(nil))
        XCTAssertTrue(AdministratorCheck.openDirectory.isAdministrator(Peer(euid: 0)))
        
        let access = { (caller: Peer?) in
            MuteAccess.app(isAdministrator: administrators.isAdministrator(caller), controlsStream: true)
        }
        XCTAssertEqual(access(Peer(euid: 501)), .write)
        XCTAssertEqual(access(Peer(euid: 502)), .standardUser)
        XCTAssertEqual(access(nil), .standardUser)
    }
    
    /// Open Directory counts root, a member of `admin` on every Mac, and never `nobody` or a user ID with no account.
    func testOpenDirectoryAnswers() {
        XCTAssertTrue(AdministratorCheck.openDirectory.isAdministrator(0))
        XCTAssertFalse(AdministratorCheck.openDirectory.isAdministrator(uid_t(bitPattern: -2)))
        XCTAssertFalse(AdministratorCheck.openDirectory.isAdministrator(3_999_999))
        XCTAssertFalse(AdministratorCheck.isMember(0, of: 3_999_999))
    }
}
