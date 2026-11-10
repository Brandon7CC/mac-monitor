//
//  IndicatorAlertSettingsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Notification settings
/// Pins this user's notification settings: off until turned on, kept under their own keys, read leniently, and the
/// status line Settings shows.
final class IndicatorAlertSettingsTests: XCTestCase {
    /// Both switches are off for a user who never set them, so nothing notifies.
    func testDefaultsAreOff() {
        let settings = IndicatorAlertSettings(defaults: makeDefaults())
        XCTAssertEqual(settings, IndicatorAlertSettings())
        XCTAssertTrue(settings.isOff)
        XCTAssertFalse(IndicatorSeverity.allCases.contains(where: settings.notifies))
    }

    /// The switches and the silenced indicators read back as saved; each switch is its own, and Low never notifies.
    func testSettingsRoundTrip() {
        let defaults = makeDefaults()
        let saved = IndicatorAlertSettings(high: false, medium: true, silenced: [UUID(), UUID()])
        saved.save(to: defaults)
        let read = IndicatorAlertSettings(defaults: defaults)
        XCTAssertEqual(read, saved)
        XCTAssertFalse(read.isOff)
        XCTAssertEqual(IndicatorSeverity.allCases.filter(read.notifies), [.medium])
        XCTAssertEqual(IndicatorAlertSettings(high: true).isOff, false)
    }

    /// A silenced entry that isn't a UUID is dropped, and the rest are kept.
    func testSilencedEntriesThatArentUUIDsAreDropped() {
        let defaults = makeDefaults()
        let id = UUID()
        defaults.set([id.uuidString, "not a uuid", 7], forKey: IndicatorAlertSettings.silencedKey)
        XCTAssertEqual(IndicatorAlertSettings(defaults: defaults).silenced, [id])
    }

    /// Saving touches only the notification keys: never the indicator view switches, whose lenient decode would drop
    /// them all on an older read of a key it doesn't know.
    func testSavingLeavesTheViewSwitchesAlone() {
        let defaults = makeDefaults()
        defaults.set(Data("views".utf8), forKey: IndicatorOverlay.key)
        let before = Set(defaults.dictionaryRepresentation().keys)
        IndicatorAlertSettings(high: true, medium: true, silenced: [UUID()]).save(to: defaults)
        XCTAssertEqual(defaults.data(forKey: IndicatorOverlay.key), Data("views".utf8))
        XCTAssertEqual(Set(defaults.dictionaryRepresentation().keys).subtracting(before),
                       [IndicatorAlertSettings.highKey, IndicatorAlertSettings.mediumKey,
                        IndicatorAlertSettings.silencedKey])
    }

    /// The status line is the first that applies: macOS refusing, notifications off, quiet, not asked yet, then the
    /// Security Extension, then another user's stream; none while they can show. Only not asked offers to ask.
    func testTheStatusIsTheFirstThatApplies() {
        typealias Status = IndicatorAlertStatus
        XCTAssertEqual(Status.current(authorization: .notAllowed, connection: .unavailable, streamOwned: true),
                       .notAllowed)
        XCTAssertEqual(Status.current(authorization: .denied, connection: .unavailable, streamOwned: true), .denied)
        XCTAssertEqual(Status.current(authorization: .quiet, connection: .unavailable, streamOwned: true), .quiet)
        XCTAssertEqual(Status.current(authorization: .authorized, connection: .unavailable, streamOwned: true),
                       .needsSecurityExtension)
        XCTAssertEqual(Status.current(authorization: .notDetermined, connection: .unavailable, streamOwned: true),
                       .notAsked)
        XCTAssertEqual(Status.current(authorization: .authorized, connection: .connected, streamOwned: true),
                       .streamOwned)
        XCTAssertNil(Status.current(authorization: .authorized, connection: .waiting, streamOwned: false))
        let all: [Status] = [.notAllowed, .denied, .quiet, .notAsked, .needsSecurityExtension, .streamOwned]
        XCTAssertEqual(all.filter(\.opensNotificationSettings), [.denied, .quiet])
        XCTAssertEqual(all.filter(\.requestsAuthorization), [.notAsked])
        XCTAssertEqual(Status.notificationSettingsURL(for: "com.swiftlydetecting.agent")?.absoluteString,
                       "x-apple.systempreferences:com.apple.Notifications-Settings.extension"
                       + "?id=com.swiftlydetecting.agent")
    }
}
