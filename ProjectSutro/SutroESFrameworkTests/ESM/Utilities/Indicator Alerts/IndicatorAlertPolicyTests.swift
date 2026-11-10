//
//  IndicatorAlertPolicyTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Which matches notify
/// Pins which of an event's hits a notification is for: only switched-on severities, never Low, only the Security
/// Extension's, never a silenced or disabled indicator, the strongest first, and the rest named.
final class IndicatorAlertPolicyTests: XCTestCase {
    /// Both switches on.
    private let both = IndicatorAlertSettings(high: true, medium: true)

    /// - Parameters:
    ///   - hits: An event's hits.
    ///   - settings: The settings.
    ///   - disabled: The indicators known to be off.
    /// - Returns: The name of the indicator its notification is for, or `nil`.
    private func picked(_ hits: [IndicatorHit]?, _ settings: IndicatorAlertSettings,
                        disabled: Set<UUID> = []) throws -> String? {
        IndicatorAlertPolicy.pick(try alertMessage(hits), settings: settings, disabled: disabled)?.indicator.name
    }

    /// Only a switched-on severity notifies, each switch on its own, and Low never does.
    func testOnlySwitchedOnSeveritiesNotify() throws {
        let (high, medium, low) = (alertHit("XProtect", .high), alertHit("Dylib", .medium), alertHit("Login", .low))
        XCTAssertNil(try picked([high, medium, low], IndicatorAlertSettings()))
        XCTAssertEqual(try picked([medium, low], IndicatorAlertSettings(medium: true)), "Dylib")
        XCTAssertNil(try picked([medium, low], IndicatorAlertSettings(high: true)))
        XCTAssertEqual(try picked([medium, high], IndicatorAlertSettings(high: true)), "XProtect")
        XCTAssertNil(try picked([low], both))
    }

    /// A hit matched by an export, or by a producer this build doesn't know, never notifies.
    func testOnlyTheSecurityExtensionsHitsNotify() throws {
        XCTAssertNil(try picked([alertHit("Export", .high, evaluatedBy: .export)], both))
        XCTAssertNil(try picked([alertHit("Other", .high, evaluatedBy: .other("x"))], both))
    }

    /// A silenced indicator never notifies, but another eligible hit on the same event still does.
    func testASilencedIndicatorDoesntNotify() throws {
        let (high, medium) = (alertHit("XProtect", .high), alertHit("Dylib", .medium))
        let silenced = IndicatorAlertSettings(high: true, medium: true, silenced: [high.id])
        XCTAssertEqual(try picked([high, medium], silenced), "Dylib")
        XCTAssertNil(try picked([high], silenced))
    }

    /// An indicator known to be off never notifies; one this Mac Monitor doesn't know isn't suppressed.
    func testAKnownDisabledIndicatorDoesntNotify() throws {
        let hit = alertHit("Dylib")
        XCTAssertNil(try picked([hit], both, disabled: [hit.id]))
        XCTAssertEqual(try picked([hit], both, disabled: [UUID()]), "Dylib")
    }

    /// An event nothing evaluated (a 3.0 Security Extension's), or one that matched nothing, gives nothing.
    func testEventsWithoutHitsGiveNothing() throws {
        XCTAssertNil(try picked(nil, both))
        XCTAssertNil(try picked([], both))
    }

    /// The strongest eligible hit wins, ties going to the set's order; the others, eligible or not, are named
    /// strongest first, two of them, ties in the set's order, with a count of the rest.
    func testTheStrongestHitWinsAndTheRestAreNamed() throws {
        let hits = [alertHit("Ran a script", .low), alertHit("Dylib", .medium), alertHit("Login hook", .medium),
                    alertHit("XProtect", .high), alertHit("Adhoc", .low), alertHit("Plist", .low)]
        let event = try XCTUnwrap(IndicatorAlertPolicy.pick(try alertMessage(hits), settings: both, disabled: []))
        XCTAssertEqual(event.indicator.name, "XProtect")
        XCTAssertEqual(event.others, ["Dylib", "Login hook"])
        XCTAssertEqual(event.moreOthers, 3)
        let medium = try XCTUnwrap(IndicatorAlertPolicy.pick(try alertMessage(hits),
                                                             settings: IndicatorAlertSettings(medium: true),
                                                             disabled: []))
        XCTAssertEqual(medium.indicator.name, "Dylib", "Ties go to the set's order")
        XCTAssertEqual(medium.others, ["XProtect", "Login hook"])
        let lows = [alertHit("Low 1", .low), alertHit("Low 2", .low), alertHit("High", .high), alertHit("Low 3", .low)]
        let tied = try XCTUnwrap(IndicatorAlertPolicy.pick(try alertMessage(lows), settings: both, disabled: []))
        XCTAssertEqual(tied.others, ["Low 1", "Low 2"], "Named others tie in the set's order too")
        XCTAssertEqual(tied.moreOthers, 1)
    }

    /// An event's age is by the wall clock, and never negative.
    func testAgeIsByTheWallClock() throws {
        let now = Date()
        let event = try XCTUnwrap(IndicatorAlertPolicy.pick(try alertMessage([alertHit("Dylib")],
                                                                             time: now.addingTimeInterval(-121)),
                                                            settings: both, disabled: []))
        XCTAssertEqual(IndicatorAlertPolicy.age(of: event, now: now), 121, accuracy: 0.001)
        XCTAssertEqual(IndicatorAlertPolicy.age(of: event, now: now.addingTimeInterval(-600)), 0)
    }

    /// The candidate holds the process and the event as a notification names them: its user only when it isn't
    /// this app's, and its signing.
    func testTheCandidateDescribesTheProcess() throws {
        let hit = alertHit("Dylib")
        let message = try alertMessage([hit]) { message in
            message.process.euid = 0
            message.process.euid_human = "root"
            message.process.signing_id = nil
            message.target_path = "/tmp/x"
        }
        let event = IndicatorAlertEvent(message, top: hit, others: [], appUser: 501)
        XCTAssertEqual(event.user, "root")
        XCTAssertTrue(event.isUnsigned)
        XCTAssertNil(event.signingID)
        XCTAssertEqual(event.targetPath, "/tmp/x")
        XCTAssertEqual(event.eventName, "exec")
        XCTAssertNil(IndicatorAlertEvent(message, top: hit, others: [], appUser: 0).user)
    }
}
