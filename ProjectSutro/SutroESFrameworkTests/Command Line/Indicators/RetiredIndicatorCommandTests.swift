//
//  RetiredIndicatorCommandTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - macmonitor indicators and a dropped osascript
/// Runs `macmonitor indicators list` and `edit --restore` end to end against a Mac whose saved set the build before
/// this one wrote with osascript in it, which 3.1.0 stopped shipping: it's listed only when its rule was edited, and
/// restoring it fails cleanly (65) either way, since this build has no osascript to restore.
final class RetiredIndicatorCommandTests: XCTestCase {
    private var savedMutes = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))

    /// A mute set in a fresh directory.
    ///
    /// - Throws: If the directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        savedMutes = SavedMuteSet(testing: try makeMuteStore())
    }

    /// A set the build before this one saved, with osascript as given.
    ///
    /// - Parameter osascript: osascript as the Mac had it.
    /// - Returns: The set, not loaded yet.
    /// - Throws: If the directory or the file can't be made.
    private func set(with osascript: Indicator) throws -> SavedIndicatorSet {
        let directory = try makeIndicatorDirectory()
        let saved = try savedWithOsascript(osascript)
        try writeIndicatorFile(JSONSerialization.data(withJSONObject: ["version": IndicatorFile.currentVersion,
                                                                       "saved": saved]), in: directory)
        return try makeSavedIndicatorSet(in: directory)
    }

    /// Run one indicators command against a set and wait for it. Nothing may ask.
    ///
    /// - Parameters:
    ///   - invocation: The command.
    ///   - set: The Mac's set.
    /// - Returns: What it did.
    private func run(_ invocation: IndicatorInvocation, against set: SavedIndicatorSet) -> IndicatorRun {
        runIndicators(invocation, savedMutes: savedMutes, savedIndicators: set, readFile: { _ in Data() }) { _ in
            XCTFail("asked")
            return false
        }
    }

    /// An unedited osascript, though turned off, is gone: not listed, and neither its ID nor its name finds an
    /// indicator to restore.
    func testAnUneditedOsascriptIsGone() throws {
        var osascript = try droppedOsascript()
        osascript.isEnabled = false
        let set = try set(with: osascript)
        let listed = run(.list(), against: set)
        XCTAssertEqual(listed.rows.count, Indicator.defaults.count)
        XCTAssertFalse(listed.output.contains("osascript"))
        let id = Self.osascriptID.uuidString
        XCTAssertEqual(run(.edit(IndicatorEdit(id, .restore)), against: set).failure,
                       CommandLineFailure(.dataError, """
                           No indicator has the ID or name “\(id)”. Run 'macmonitor indicators list' to see them.
                           """))
        XCTAssertEqual(run(.edit(IndicatorEdit("osascript", .restore)), against: set).failure?.exit, .dataError)
        XCTAssertEqual(try savedIndicators(in: set.store.directory), Indicator.defaults, "Nothing changed")
    }

    /// An edited osascript is listed, in its place and with its severity, as the user's own, so `--restore` has
    /// nothing to bring back and changes nothing.
    func testAnEditedOsascriptIsTheUsersOwn() throws {
        let edited = try editedOsascript()
        let set = try set(with: edited)
        let row = try XCTUnwrap(run(.list(), against: set).rows.first { $0.hasSuffix("   osascript") })
        XCTAssertTrue(row.hasPrefix("on "), row)
        XCTAssertTrue(row.contains(" low ") && row.contains(Self.osascriptID.uuidString), row)
        XCTAssertEqual(run(.edit(IndicatorEdit(Self.osascriptID.uuidString, .restore)), against: set).failure,
                       CommandLineFailure(.dataError, """
                           “osascript” isn't one of Mac Monitor's own, so it has nothing to restore.
                           """))
        let expected = try defaultsWithOsascript().map { $0.id == Self.osascriptID ? edited : $0 }
        XCTAssertEqual(try savedIndicators(in: set.store.directory), expected)
    }
}
