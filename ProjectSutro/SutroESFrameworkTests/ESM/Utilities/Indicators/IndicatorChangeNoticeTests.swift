//
//  IndicatorChangeNoticeTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import notify
@testable import SutroESFramework


// MARK: - The indicator set's change notice
/// Pins how Mac Monitor learns of a change another client makes to the Mac's indicator set: the Security Extension's
/// service posts a Darwin notification after each one, and Mac Monitor's engine asks for the set again, at most once a
/// second, and only once it has asked before. Each test posts a notification of its own.
final class IndicatorChangeNoticeTests: XCTestCase {
    /// A notification nobody else posts.
    private let notification = "com.swiftlydetecting.agent.tests.indicators.\(UUID().uuidString)"

    /// Run the main queue until a condition holds, as the engine's replies and the notice's calls arrive there.
    ///
    /// - Parameters:
    ///   - timeout: How long to wait, in seconds.
    ///   - condition: Checked between turns of the main run loop.
    /// - Returns: Whether it holds.
    private func runMain(timeout: TimeInterval = 5, until condition: () -> Bool) -> Bool {
        let deadline = Date(timeIntervalSinceNow: timeout)
        while !condition(), Date() < deadline {
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.01))
        }
        return condition()
    }

    /// Every change `sudo macmonitor indicators` makes while Mac Monitor is open shows in Mac Monitor's set, with
    /// nothing asked for by hand: an add, an edit and a removal, through the Security Extension's `StreamService`,
    /// posted by its `SensorService`.
    func testChangesMacmonitorMakesShowInMacMonitor() throws {
        let set = try makeSavedIndicatorSet()
        set.load()
        let savedMutes = SavedMuteSet(testing: try makeMuteStore())
        let service = SensorServiceHarness(savedMutes: savedMutes, savedIndicators: set,
                                           commandLineAccess: CommandLineAccessStore(defaults: makeDefaults()),
                                           switches: EnrichmentSwitchStore(defaults: makeDefaults()),
                                           changes: notification)
        defer { withExtendedLifetime(service) {} }
        let engine = IndicatorEngine(defaults: makeDefaults())
        engine.connect(transport(to: set), changes: notification)
        XCTAssertEqual(send(IndicatorRequest(.list), through: engine)?.status, .ok)
        /// Run one `macmonitor indicators` command against the set, and fail the test if it fails.
        ///
        /// - Parameter invocation: The command.
        func run(_ invocation: IndicatorInvocation) {
            let ran = runIndicators(invocation, savedMutes: savedMutes, savedIndicators: set)
            XCTAssertNoThrow(try ran.result?.get(), "\(invocation)")
        }

        run(.add(name: "Curl", predicate: IndicatorCommandLineTests.curl, severity: .high))
        _ = runMain { engine.indicators.contains { $0.name == "Curl" } }
        let added = try XCTUnwrap(engine.indicators.first { $0.name == "Curl" }, "An add shows")

        run(.edit(IndicatorEdit(added.id.uuidString, .values([.severity: "low"]))))
        XCTAssertTrue(runMain { engine.indicators.first { $0.id == added.id }?.severity == .low }, "An edit shows")

        run(.remove([added.id.uuidString]))
        XCTAssertTrue(runMain { !engine.indicators.contains { $0.id == added.id } }, "A removal shows")
        XCTAssertEqual(engine.indicators, Indicator.defaults)
    }

    /// A post before the set was first asked for asks nothing, so nothing goes to a Security Extension before the
    /// handshake. Once asked, a post asks again.
    func testAPostAsksOnlyOnceTheSetWasAskedFor() throws {
        let set = try makeSavedIndicatorSet()
        set.load()
        let engine = IndicatorEngine(defaults: makeDefaults())
        var requests = 0
        let relay = transport(to: set)
        engine.connect({ request, reply in
            requests += 1
            relay(request, reply)
        }, changes: notification)

        notify_post(notification)
        XCTAssertFalse(runMain(timeout: 0.5) { requests > 0 }, "Nothing is asked before the handshake")
        XCTAssertEqual(engine.connection, .waiting)

        send(IndicatorRequest(.list), through: engine)
        XCTAssertEqual(requests, 1)
        notify_post(notification)
        XCTAssertTrue(runMain { requests == 2 }, "A post asks again")
    }

    /// A post while the first list is on its way asks again, so a change made meanwhile isn't hidden by the reply
    /// from before it, as when `macmonitor` changes the set just after Mac Monitor's handshake.
    func testAPostWhileTheFirstListIsOnItsWayAsksAgain() throws {
        let set = try makeSavedIndicatorSet()
        set.load()
        let engine = IndicatorEngine(defaults: makeDefaults())
        let relay = transport(to: set)
        var requests = 0
        var held: (() -> Void)?
        engine.connect({ request, reply in
            requests += 1
            if requests == 1 { held = { relay(request, reply) } } else { relay(request, reply) }
        }, changes: notification)

        engine.refresh()
        XCTAssertEqual(engine.connection, .waiting, "The first list is on its way")
        notify_post(notification)
        _ = runMain(timeout: 0.5) { requests > 1 }
        held?()
        XCTAssertTrue(runMain { requests == 2 && engine.connection == .connected }, "The post asks again")
    }

    /// A flood of posts calls back once at once, then once more after the interval for those that came meanwhile,
    /// and no more.
    func testAFloodCallsBackOnceAnInterval() {
        var calls: [Date] = []
        let notice = IndicatorChangeNotice(name: notification, interval: .milliseconds(300)) { calls.append(Date()) }
        for _ in 0..<5 { notice.notified() }
        XCTAssertEqual(calls.count, 1, "The first post calls back at once")

        XCTAssertTrue(runMain { calls.count == 2 }, "The rest call back once after the interval")
        XCTAssertGreaterThanOrEqual(calls[1].timeIntervalSince(calls[0]), 0.25)
        XCTAssertFalse(runMain(timeout: 0.6) { calls.count > 2 }, "Nothing more")
    }
}
