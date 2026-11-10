//
//  CommandLineAccessStoreTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Keeping the level
/// The Security Extension's store: root only until changed, fails closed, and keeps each change.
final class CommandLineAccessStoreTests: XCTestCase {
    private var suite: String!
    private var defaults: UserDefaults!
    private var store: CommandLineAccessStore!

    override func setUp() {
        super.setUp()
        suite = "CommandLineAccessStoreTests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)
        store = CommandLineAccessStore(defaults: defaults)
    }

    override func tearDown() {
        defaults.removePersistentDomain(forName: suite)
        super.tearDown()
    }

    /// Nothing stored, or anything that isn't a level, is root only.
    func testItFailsClosed() {
        XCTAssertEqual(store.access, .rootOnly)
        for value: Any in ["everyone", "", 1, true] {
            defaults.set(value, forKey: CommandLineAccessStore.key)
            XCTAssertEqual(store.access, .rootOnly, "\(value)")
        }
    }

    /// Every change, wider or narrower, is kept, and a new store reads it back.
    func testItKeepsEachChange() {
        for access in [CommandLineAccess.streaming, .streamingAndChanges, .streaming, .rootOnly, .streamingAndChanges] {
            XCTAssertEqual(store.change(to: access), .done)
            XCTAssertEqual(store.access, access)
            XCTAssertEqual(CommandLineAccessStore(defaults: defaults).access, access, "Kept")
        }
    }

    /// The level that lets anyone change mutes and indicators is stored as `streamingAndChanges`. Its name before
    /// 3.1, `streamingAndMuting`, never shipped, so it reads as anything unknown does: root only.
    func testTheChangesLevelIsStoredByItsName() {
        XCTAssertEqual(store.change(to: .streamingAndChanges), .done)
        XCTAssertEqual(defaults.string(forKey: CommandLineAccessStore.key), "streamingAndChanges")
        defaults.set("streamingAndMuting", forKey: CommandLineAccessStore.key)
        XCTAssertEqual(store.access, .rootOnly)
    }

    /// Every outcome but done tells the user something, and survives the trip over XPC.
    func testOutcomes() {
        for outcome in CommandLineAccessChange.allCases {
            XCTAssertEqual(CommandLineAccessChange(rawValue: outcome.rawValue), outcome)
            XCTAssertEqual(outcome.message == nil, outcome == .done, "\(outcome)")
        }
    }
}
