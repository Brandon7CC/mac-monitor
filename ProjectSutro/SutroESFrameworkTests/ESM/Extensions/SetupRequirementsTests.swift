//
//  SetupRequirementsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/22/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Setup requirements
/// Pins what the requirements checklist shows: each requirement done, needed, or not checkable until an earlier one
/// is, from where Mac Monitor runs, the Security Extension's state and Endpoint Security's answer.
final class SetupRequirementsTests: XCTestCase {
    /// The requirements for a Mac Monitor in Applications on macOS 15 with SIP on.
    ///
    /// - Parameters:
    ///   - state: The Security Extension.
    ///   - client: Endpoint Security's answer.
    ///   - location: Where Mac Monitor runs from.
    ///   - sipDisabled: Is SIP off?
    /// - Returns: The requirements.
    private func requirements(_ state: SetupRequirements.ExtensionState, _ client: NewClientResult = .waiting,
                              at location: SetupRequirements.Location = .applications,
                              sipDisabled: Bool = false) -> SetupRequirements {
        SetupRequirements(location: location, extensionState: state, client: client, sipDisabled: sipDisabled,
                          hasExtensionsPane: true)
    }

    /// Each requirement's status, in order.
    ///
    /// - Parameter requirements: The requirements.
    /// - Returns: The statuses.
    private func statuses(_ requirements: SetupRequirements) -> [SetupRequirements.Status] {
        requirements.rows.map(\.status)
    }

    /// A first launch: the extension isn't installed, and installing it is the user's to start, since macOS then
    /// shows its prompt. Mac Monitor activates one at launch only once it runs.
    func testAFirstLaunchNeedsTheExtensionInstalled() {
        let first = requirements(.notInstalled)
        XCTAssertEqual(statuses(first), [.done, .needed, .pending])
        XCTAssertEqual(first.nextStep?.action, .installExtension)
        XCTAssertEqual(first.nextStep?.detail,
                       "Mac Monitor communicates with Endpoint Security via a System Extension.")
        XCTAssertTrue(first.isSettled)
        typealias State = SetupRequirements.ExtensionState
        let launches: [State] = [.checking, .notInstalled, .awaitingApproval, .disabled, .needsRestart, .wrongLocation,
                                 .failed("x")]
        XCTAssertEqual(launches.filter(\.activatesAtLaunch), [])
        XCTAssertTrue(State.running(version: nil).activatesAtLaunch)
    }

    /// Once installed, the extension awaits approval, so Full Disk Access can't be checked yet.
    func testAnInstalledExtensionNeedsAllowing() {
        let first = requirements(.awaitingApproval)
        XCTAssertEqual(statuses(first), [.done, .needed, .pending])
        XCTAssertEqual(first.nextStep?.action, .openExtensions)
        XCTAssertTrue(first.nextStep?.detail.contains("Login Items & Extensions") == true)
        XCTAssertTrue(first.isSettled)
        XCTAssertFalse(first.isReady)
        let older = SetupRequirements(location: .applications, extensionState: .awaitingApproval, client: .waiting,
                                      sipDisabled: false, hasExtensionsPane: false)
        XCTAssertTrue(older.nextStep?.detail.contains("Privacy & Security") == true)
    }

    /// Running without Full Disk Access needs it. With it, or with SIP off, everything is done.
    func testFullDiskAccess() {
        XCTAssertEqual(statuses(requirements(.running(version: "3.0.0 (1)"), .notPermitted)), [.done, .done, .needed])
        XCTAssertEqual(requirements(.running(version: nil), .notPermitted).nextStep?.action, .openFullDiskAccess)
        let ready = requirements(.running(version: "3.0.0 (1)"), .success)
        XCTAssertTrue(ready.isReady)
        XCTAssertNil(ready.nextStep)
        XCTAssertEqual(ready.rows[1].detail, "Version 3.0.0 (1)")
        XCTAssertEqual(ready.rows[2].title, "Full Disk Access is allowed")
        XCTAssertEqual(requirements(.running(version: nil), .streamOwned).rows[2].title, "Full Disk Access is allowed")
        let sipOff = requirements(.running(version: nil), .success, sipDisabled: true)
        XCTAssertTrue(sipOff.isReady)
        XCTAssertEqual(sipOff.rows[2].title, "Full Disk Access isn't needed")
        XCTAssertFalse(requirements(.running(version: nil), .waiting).isSettled, "Waiting on Endpoint Security")
        XCTAssertTrue(requirements(.running(version: nil), .streamOwned).isReady, "Another Mac Monitor records")
    }

    /// An answer from Endpoint Security means the extension runs, whatever macOS last reported.
    func testAnAnswerMeansTheExtensionRuns() {
        XCTAssertEqual(statuses(requirements(.checking, .notPermitted)), [.done, .done, .needed])
        XCTAssertEqual(statuses(requirements(.checking, .internalSubsystem)), [.done, .pending, .pending])
    }

    /// Outside Applications only matters when macOS refuses it there. A translocated copy never works.
    func testTheLocation() {
        let developer = requirements(.running(version: nil), .success,
                                     at: .elsewhere("/Users/marcus/mac-monitor/Mac Monitor.app"))
        XCTAssertTrue(developer.isReady)
        let refused = requirements(.wrongLocation, at: .elsewhere("/Users/marcus/Downloads/Mac Monitor.app"))
        XCTAssertEqual(statuses(refused), [.needed, .pending, .pending])
        XCTAssertEqual(refused.nextStep?.action, .showInFinder)
        XCTAssertEqual(statuses(requirements(.checking, at: .translocated)), [.needed, .pending, .pending])
        XCTAssertEqual(SetupRequirements.Location.of("/Applications/Mac Monitor.app"), .applications)
        XCTAssertEqual(SetupRequirements.Location.of("/private/var/folders/x/AppTranslocation/y/d/Mac Monitor.app"),
                       .translocated)
    }

    /// Turned off, restart needed and failed each say so.
    func testTheExtensionsOtherStates() {
        XCTAssertEqual(requirements(.disabled).rows[1].title, "Turn the Security Extension back on")
        XCTAssertEqual(statuses(requirements(.needsRestart)), [.done, .restart, .pending])
        XCTAssertTrue(requirements(.failed("Its code signature isn't valid.")).rows[1].detail
            .hasPrefix("macOS said: Its code signature isn't valid."))
        XCTAssertFalse(requirements(.checking).isSettled)
    }

    /// macOS's report: an enabled copy runs, else one awaiting approval, else one is off. What the activation said
    /// wins.
    func testWhatMacOSReports() {
        typealias State = SetupRequirements.ExtensionState
        let old = SetupRequirements.ExtensionReport(isEnabled: true, isAwaitingApproval: false, isUninstalling: true,
                                                    version: "2.1.0 (5)")
        let awaiting = SetupRequirements.ExtensionReport(isEnabled: false, isAwaitingApproval: true,
                                                         isUninstalling: false, version: "3.0.0 (1)")
        let off = SetupRequirements.ExtensionReport(isEnabled: false, isAwaitingApproval: false, isUninstalling: false,
                                                    version: "3.0.0 (1)")
        let on = SetupRequirements.ExtensionReport(isEnabled: true, isAwaitingApproval: false, isUninstalling: false,
                                                   version: "3.0.0 (1)")
        XCTAssertEqual(State.reported([old, on], current: .checking), .running(version: "3.0.0 (1)"))
        XCTAssertEqual(State.reported([old, awaiting], current: .checking), .awaitingApproval)
        XCTAssertEqual(State.reported([off], current: .running(version: nil)), .disabled)
        XCTAssertEqual(State.reported([old], current: .checking), .notInstalled)
        XCTAssertEqual(State.reported([on], current: .needsRestart), .needsRestart)
        XCTAssertEqual(State.reported([on], current: .wrongLocation), .wrongLocation)
    }
}
