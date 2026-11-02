//
//  UserNamesTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/25/26.
//

import XCTest
import notify
@testable import SutroESFramework


// MARK: - User names
/// Pins how events name users: a name is read from the user database once and remembered until the database says its
/// users changed, an ID with no user only briefly, and a lookup the database changed during is never remembered.
final class UserNamesTests: XCTestCase {
    /// Counts the lookups a fake user database answers.
    private final class Database {
        var lookups = 0
        var names: [uid_t: String] = [501: "alice"]
        /// Runs during a lookup, before it returns.
        var during: () -> Void = {}

        func name(of uid: uid_t) -> String? {
            lookups += 1
            during()
            return names[uid]
        }
    }

    /// A notification name no other test or process posts.
    private let notification = "com.swiftlydetecting.tests.UserNames.\(UUID().uuidString)"
    /// The user database the names are read from.
    private let database = Database()

    /// A name is read once, then remembered.
    func testRemembersNames() {
        let names = UserNames(changedBy: [notification], lookUp: database.name(of:))
        XCTAssertEqual((0..<3).map { _ in names.name(of: 501) }, ["alice", "alice", "alice"])
        XCTAssertEqual(database.lookups, 1)
    }

    /// A name is remembered for as long as a hit lives, then read again: a directory server's rename posts nothing.
    func testRemembersNamesForAWhile() {
        let names = UserNames(changedBy: [notification], hitLifetime: 0, lookUp: database.name(of:))
        XCTAssertEqual(names.name(of: 501), "alice")
        database.names[501] = "alicia"
        XCTAssertEqual(names.name(of: 501), "alicia")
        XCTAssertEqual(database.lookups, 2)
    }

    /// An ID with no user is remembered for as long as a miss lives, then asked about again.
    func testRemembersMissesBriefly() {
        let long = UserNames(changedBy: [notification], lookUp: database.name(of:))
        XCTAssertNil(long.name(of: 4_242))
        XCTAssertNil(long.name(of: 4_242))
        XCTAssertEqual(database.lookups, 1)

        let brief = UserNames(changedBy: [notification], missLifetime: 0, lookUp: database.name(of:))
        XCTAssertNil(brief.name(of: 4_242))
        database.names[4_242] = "bob"
        XCTAssertEqual(brief.name(of: 4_242), "bob")
        XCTAssertEqual(database.lookups, 3)
    }

    /// Directory Services' notification forgets every name, so a renamed user is read again.
    func testForgetsWhenTheDatabaseChanges() {
        let names = UserNames(changedBy: [notification], lookUp: database.name(of:))
        XCTAssertEqual(names.name(of: 501), "alice")
        database.names[501] = "alicia"

        notify_post(notification)
        let changed = expectation(for: NSPredicate { _, _ in names.changes == 1 }, evaluatedWith: nil)
        wait(for: [changed], timeout: 10)
        XCTAssertEqual(names.name(of: 501), "alicia")
        XCTAssertEqual(database.lookups, 2)
    }

    /// A name read while the database changed may be stale, so it isn't remembered.
    func testForgetsALookupTheDatabaseChangedDuring() {
        let names = UserNames(changedBy: [notification], lookUp: database.name(of:))
        database.during = { [unowned names] in names.forget() }
        XCTAssertEqual(names.name(of: 501), "alice")
        database.during = {}
        XCTAssertEqual(names.name(of: 501), "alice")
        XCTAssertEqual(database.lookups, 2)
    }

    /// This Mac's own user database, through the names every event uses.
    func testNamesThisMacsUsers() {
        XCTAssertEqual(UserNames.databaseName(of: 0), "root")
        XCTAssertNil(UserNames.databaseName(of: uid_t.max))
        XCTAssertEqual(Process.userName(0, systemAccountsOnly: true), "root")
        XCTAssertNil(Process.userName(501, systemAccountsOnly: true), "Named a user other than a system account")
        XCTAssertEqual(Process.userName(0, systemAccountsOnly: true, remembered: false), "root")
    }
}
