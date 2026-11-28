//
//  XCTestCase+EventHold.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Holding app execs
extension XCTestCase {
    /// The process that asked Launch Services to launch the apps in a hold's tests.
    static let appLauncher = appToken(700)

    /// The target token of an app's exec: a user's process in audit session 100001.
    ///
    /// - Parameter pid: The app's pid. Its pid version is ten times that.
    /// - Returns: The token.
    static func appToken(_ pid: Int32) -> AuditToken {
        AuditToken(pid: pid, pidversion: pid * 10, asid: 100_001, auid: 501, euid: 501, ruid: 501, rgid: 20, egid: 20)
    }

    /// Launch Services' record of an app ``appLauncher`` launched.
    ///
    /// - Parameter pid: The app's pid.
    /// - Returns: The record.
    func launchRecord(of pid: pid_t) -> LaunchServicesRecord {
        LaunchServicesRecord(token: Self.appToken(pid), launchedByLaunchServices: true, hasParentASN: true,
                             parentToken: Self.appLauncher)
    }

    /// An exec made an app's, as the exec lane builds one: launchd started its job, so it's held for Launch Services.
    ///
    /// - Parameters:
    ///   - exec: The exec it's made from.
    ///   - pid: The app's pid, with its token (``appToken(_:)``).
    /// - Returns: The exec, with an `id` of its own.
    func appExec(_ exec: Message, pid: Int32) -> Message {
        var message = exec
        if case .exec(var event) = message.event {
            event.target.pid = pid
            event.target.audit_token = Self.appToken(pid)
            message.event = .exec(event)
        }
        message.setLaunchedByParent(.appJob())
        message.id = UUID()
        return message
    }

    /// The process lane's hold, whose upgrader names each launcher's executable `/path/of/<pid>`.
    ///
    /// - Parameters:
    ///   - reader: Launch Services.
    ///   - delays: When the upgrader reads, after an exec arrives.
    ///   - maxHeld: The most execs held for Launch Services.
    ///   - maxScanHeld: The most execs held for their scans.
    ///   - maxWait: The longest an exec is held.
    ///   - emitted: Keeps what the hold sends.
    /// - Returns: The hold.
    func processHold(_ reader: LaunchServicesReading, delays: [TimeInterval] = [0],
                     maxHeld: Int = EventHold.defaultMaxHeld, maxScanHeld: Int = EventHold.defaultMaxHeld,
                     maxWait: TimeInterval = 5, emitted: EmittedEvents) -> EventHold {
        let upgrader = LaunchedByParentUpgrader(reader: reader, delays: delays) { pid, _ in "/path/of/\(pid)" }
        return EventHold(eventClass: .process, upgrader: upgrader, maxHeld: maxHeld, maxScanHeld: maxScanHeld,
                         maxWait: maxWait, emit: emitted.append)
    }
}
