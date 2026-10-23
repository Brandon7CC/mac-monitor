//
//  ConsoleUserTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Who's at the console
/// Pins how the Security Extension finds the console user whose home folder the default mute set mutes: the session's
/// user, their home from the user database, and no one at the login window, in Setup Assistant, or without a usable
/// home folder. Every case but the system's own answers runs without real accounts.
final class ConsoleUserTests: XCTestCase {
    /// A source that answers with a session and a home folder.
    ///
    /// - Parameters:
    ///   - name: The session's user, or `nil` for no session.
    ///   - uid: Their user ID.
    ///   - home: The home folder the user database has for that ID, if any.
    /// - Returns: The source.
    private func source(_ name: String?, uid: uid_t = 501, home: String? = "/Users/alice") -> ConsoleUserSource {
        ConsoleUserSource(session: { name.map { ($0, uid) } }, homeFolder: { $0 == uid ? home : nil })
    }
    
    /// The session's user, with the home folder the user database has, wherever it is.
    func testTheSessionsUserAndTheirHome() {
        XCTAssertEqual(ConsoleUser.current(source("alice")), ConsoleUser(name: "alice", uid: 501, home: "/Users/alice"))
        XCTAssertEqual(ConsoleUser.current(source("bob", uid: 502, home: "/Volumes/Homes/bob"))?.home,
                       "/Volumes/Homes/bob")
        XCTAssertEqual(ConsoleUser.current(source("root", uid: 0, home: "/var/root"))?.home, "/var/root")
    }
    
    /// No session, the login window, and Setup Assistant's service account are no one.
    func testNoOneAtTheConsole() {
        XCTAssertNil(ConsoleUser.current(source(nil)))
        XCTAssertNil(ConsoleUser.current(source("loginwindow", uid: 0, home: "/var/root")))
        XCTAssertNil(ConsoleUser.current(source("_mbsetupuser", uid: 248, home: "/var/setup")))
        XCTAssertNil(ConsoleUser.current(source("")))
    }
    
    /// A user without a home folder, or with one that isn't an absolute path other than `/`, is no one to mute for.
    func testHomesThatCantBeUsed() {
        XCTAssertNil(ConsoleUser.current(source("alice", home: nil)))
        XCTAssertNil(ConsoleUser.current(source("alice", home: "")))
        XCTAssertNil(ConsoleUser.current(source("alice", home: "Users/alice")))
        XCTAssertNil(ConsoleUser.current(source("alice", home: "/")))
    }
    
    /// The user database has root's home on every Mac, and none for a user ID with no account.
    func testTheUserDatabase() {
        XCTAssertEqual(ConsoleUserSource.homeFolder(of: 0), "/var/root")
        XCTAssertNil(ConsoleUserSource.homeFolder(of: 3_999_999))
    }
}
