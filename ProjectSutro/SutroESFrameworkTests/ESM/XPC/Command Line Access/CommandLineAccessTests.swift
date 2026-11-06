//
//  CommandLineAccessTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Who may use macmonitor without sudo
/// Pins the authorization decision the Security Extension makes for every `macmonitor` request: root may do
/// everything at every level, and anyone else exactly what the level allows, administrator or not.
final class CommandLineAccessTests: XCTestCase {
    /// The whole matrix: three levels by root and two users who aren't.
    func testTheDecisionMatrix() {
        let expected: [(CommandLineAccess, uid_t, CommandLineGrant)] = [
            (.rootOnly, 0, .everything),
            (.rootOnly, 501, .refused(CommandLineAccess.needsRoot)),
            (.rootOnly, 4_294_967_294, .refused(CommandLineAccess.needsRoot)),
            (.streaming, 0, .everything),
            (.streaming, 501, .streaming),
            (.streaming, 4_294_967_294, .streaming),
            (.streamingAndMuting, 0, .everything),
            (.streamingAndMuting, 501, .everything),
            (.streamingAndMuting, 4_294_967_294, .everything),
        ]
        for (access, euid, result) in expected {
            XCTAssertEqual(access.grant(forEffectiveUser: euid), result, "\(access) euid \(euid)")
        }
    }

    /// Each grant streams and reaches the saved mute set as far as it says, and only a refusal has a reason.
    func testWhatEachGrantMayDo() {
        let refused = CommandLineGrant.refused("No.")
        XCTAssertFalse(refused.mayStream)
        XCTAssertNil(refused.muteAccess)
        XCTAssertEqual(refused.refusal, "No.")
        XCTAssertTrue(CommandLineGrant.streaming.mayStream)
        XCTAssertEqual(CommandLineGrant.streaming.muteAccess, .list)
        XCTAssertNil(CommandLineGrant.streaming.refusal)
        XCTAssertTrue(CommandLineGrant.everything.mayStream)
        XCTAssertEqual(CommandLineGrant.everything.muteAccess, .write)
        XCTAssertNil(CommandLineGrant.everything.refusal)
    }

    /// Listing is all ``MuteAccess/list`` allows, and the refusals point at the setting without asking for an
    /// administrator.
    func testTheRefusalsPointAtTheSetting() {
        XCTAssertEqual(MuteAccess.list.refusal?.status, .refused)
        XCTAssertEqual(MuteAccess.list.refusal?.problem, CommandLineAccess.needsMuteChanges)
        for refusal in [CommandLineAccess.needsRoot, CommandLineAccess.needsMuteChanges] {
            XCTAssertTrue(refusal.contains(CommandLineAccess.setting), refusal)
            XCTAssertFalse(refusal.lowercased().contains("administrator"), refusal)
        }
    }

    /// The levels are ordered from narrowest to widest, start at root only, and survive the trip over XPC as their
    /// names.
    func testTheLevelsAreOrdered() {
        XCTAssertEqual(CommandLineAccess.allCases.first, .rootOnly)
        XCTAssertLessThan(CommandLineAccess.rootOnly, .streaming)
        XCTAssertLessThan(CommandLineAccess.streaming, .streamingAndMuting)
        for access in CommandLineAccess.allCases {
            XCTAssertEqual(CommandLineAccess(rawValue: access.rawValue), access)
        }
    }

    /// A request with no connection may do nothing, at any level. (`StreamSessionTests` checks the live rule over a
    /// real connection.)
    func testNoConnectionMayDoNothing() {
        for access in CommandLineAccess.allCases {
            XCTAssertEqual(StreamService.granting { access }(nil), .refused(CommandLineAccess.needsRoot), "\(access)")
        }
    }
}
