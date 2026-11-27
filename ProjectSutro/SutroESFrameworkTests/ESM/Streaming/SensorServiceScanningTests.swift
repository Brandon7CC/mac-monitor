//
//  SensorServiceScanningTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Settings turning scanning on and off
/// Pins scanning written files as Settings > General turns it on and off over real NSXPC connections: it's on until
/// turned off, it travels as ``YaraScan/subscriptionName`` beside the subscriptions, only the owner of the event stream
/// changes it, and it outlives a capture session, as subscriptions do.
final class SensorServiceScanningTests: XCTestCase {
    /// A service on fake clients, with saved sets in fresh directories.
    private func makeHarness() throws -> SensorServiceHarness {
        let suite = "SensorServiceScanningTests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        addTeardownBlock { defaults.removePersistentDomain(forName: suite) }
        return SensorServiceHarness(savedMutes: SavedMuteSet(testing: try makeMuteStore()),
                                    savedIndicators: try makeSavedIndicatorSet(),
                                    commandLineAccess: CommandLineAccessStore(defaults: defaults),
                                    switches: EnrichmentSwitchStore(defaults: defaults))
    }

    /// Whether a connection reads scanning as on.
    private func scans(_ connection: NSXPCConnection) -> Bool? {
        connection.sensor { $0.eventSubscriptions(reply: $1) }?.contains(YaraScan.subscriptionName)
    }

    /// Set scanning on or off from a connection.
    private func setScanning(_ connection: NSXPCConnection, _ enabled: Bool) -> Bool? {
        connection.sensor { $0.setSubscription(YaraScan.subscriptionName, enabled: enabled, reply: $1) }
    }

    /// Whether the rules are loaded, as a connection reads it.
    private func status(_ connection: NSXPCConnection) -> XProtectRuleStatus? {
        connection.sensor { $0.xprotectRules(reply: $1) }.flatMap {
            try? JSONDecoder().decode(XProtectRuleStatus.self, from: $0)
        }
    }

    /// Scanning starts on. The owner turns it off and on, a second Mac Monitor can't, and anyone can read it.
    func testTheOwnerTurnsScanningOnAndOff() throws {
        let harness = try makeHarness()
        let (first, second) = (harness.connect(), harness.connect())
        defer { [first, second].forEach { $0.invalidate() } }
        XCTAssertEqual(first.handshake(recording: false), .success)
        XCTAssertEqual(second.handshake(), .streamOwned)
        XCTAssertEqual(scans(first), true, "On by default")
        XCTAssertEqual(setScanning(second, false), false)
        XCTAssertEqual(scans(first), true)
        XCTAssertEqual(setScanning(first, false), true)
        XCTAssertEqual(scans(second), false)
        XCTAssertEqual(setScanning(first, true), true)
        XCTAssertEqual(scans(first), true)
    }

    /// Scanning turned off outlives a capture session: an owner that comes back gets a session that doesn't scan.
    /// ``SensorServiceRestartTests`` pins what a restart keeps.
    func testScanningOutlivesASession() throws {
        let harness = try makeHarness()
        let first = harness.connect()
        XCTAssertEqual(first.handshake(recording: false), .success)
        XCTAssertEqual(setScanning(first, false), true)
        first.invalidate()
        XCTAssertTrue(waitUntil { harness.owner == nil })
        let again = harness.connect()
        defer { again.invalidate() }
        XCTAssertEqual(again.handshake(recording: false), .success)
        XCTAssertEqual(scans(again), false)
        XCTAssertEqual(harness.scansWrittenFiles, false, "Its capture doesn't scan")
    }

    /// Any Mac Monitor can ask whether the rules are loaded. They wait while capture doesn't run. While capture scans,
    /// the scanner says what it holds, here no rules and why, with Close or Exec events. They wait again without
    /// either. Scanning off says so.
    func testAnyoneCanAskWhetherTheRulesAreLoaded() throws {
        let harness = try makeHarness()
        let (first, second) = (harness.connect(), harness.connect())
        defer { [first, second].forEach { $0.invalidate() } }
        XCTAssertEqual(status(second), XProtectRuleStatus(state: .waiting), "No capture yet")
        XCTAssertEqual(first.handshake(recording: false), .success)
        let failed = XProtectRuleStatus(state: .failed, problems: ["No rules in tests."])
        XCTAssertEqual(status(second), failed)
        XCTAssertEqual(first.sensor { $0.setSubscription("ES_EVENT_TYPE_NOTIFY_CLOSE", enabled: false, reply: $1) },
                       true)
        XCTAssertEqual(status(second), failed, "Execs are still captured")
        XCTAssertEqual(first.sensor { $0.setSubscription("ES_EVENT_TYPE_NOTIFY_EXEC", enabled: false, reply: $1) },
                       true)
        XCTAssertEqual(status(second), XProtectRuleStatus(state: .waiting), "No closes or execs")
        XCTAssertEqual(setScanning(first, false), true)
        XCTAssertEqual(status(second), XProtectRuleStatus(state: .off))
    }
}
