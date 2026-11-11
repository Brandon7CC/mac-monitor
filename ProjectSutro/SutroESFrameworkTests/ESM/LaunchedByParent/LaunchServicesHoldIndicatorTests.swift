//
//  LaunchServicesHoldIndicatorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Verdicts on execs
/// Pins the verdicts an exec carries. Execs are never built from raw messages in the tests (``RawMessageFixture``),
/// so they're read from eslogger's JSON and stamped as the serializer stamps what it builds. A stamped app exec held
/// for Launch Services keeps its verdicts whichever way it leaves the hold: settled with Launch Services' answer,
/// sent at once past the hold's bound, or released as the lane closes. Its undetermined indicators stay with it too.
final class LaunchServicesHoldIndicatorTests: XCTestCase {
    /// The process that asked Launch Services to launch the apps.
    private let launcher = LaunchServicesHoldIndicatorTests.target(700)
    /// Events the hold sent, in order.
    private let emitted = EmittedEvents()
    /// eslogger's exec of curl, which the apps' execs are made from.
    private var exec: Message!

    /// Read the exec, and make it curl's.
    ///
    /// - Throws: The error reading it.
    override func setUpWithError() throws {
        exec = try importRecord(try esloggerExec(parent: (1, 1), args: ["curl", "-sO", "https://example.com/x"]))
        guard case .exec(var event) = exec.event else { return XCTFail("Not an exec") }
        event.target.executable?.path = "/usr/bin/curl"
        exec.event = .exec(event)
    }

    /// An exec imported from eslogger is stamped with the shipped indicators it matches, "Download tool" among them,
    /// as Mac Monitor's matching finds them.
    func testAnImportedExecIsStamped() throws {
        var message = try XCTUnwrap(exec)
        XCTAssertNil(message.indicators, "eslogger's records carry no verdicts")
        var values = MessageValueCache()
        Self.shippedIndicators.stamp(&message, values: &values)
        let ids = try XCTUnwrap(message.indicators).hits.map(\.id)
        XCTAssertTrue(ids.contains(try shippedID("Download tool")), "\(ids)")
        XCTAssertEqual(ids, try matcherHits(message))
        assertStamped(message.indicators)
        XCTAssertEqual(try JSONDecoder().decode(Message.self, from: JSONEncoder().encode(message)).indicators,
                       message.indicators, "The verdicts travel on the wire")
    }

    /// A held exec settled with Launch Services' answer leaves with its verdicts. The hold is kept until then: its
    /// lookups only hold it weakly.
    func testVerdictsSurviveSettling() throws {
        let reader = FakeLaunchServicesReader { pid, _ in self.launch(of: pid) }
        let stamped = try appExec(pid: 606)
        let hold = hold(reader)
        hold.hold(stamped)
        let sent = try sentExecs(1)
        XCTAssertEqual(sent.first?.indicators, stamped.indicators)
        XCTAssertEqual(launchedByParent(of: sent.first)?.source, .launchServices)
    }

    /// A rule on an exec's launched-by parent is evaluated again once Launch Services names the launcher, so the exec
    /// leaves with the verdict its record gives. A set that reads no launched-by parent isn't evaluated again.
    func testAParentRuleIsEvaluatedAgainOnSettling() throws {
        let rule = ownIndicator("Launched by the launcher", #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND "#
                                + #"event.exec.launched_by_parent.path == "/path/of/700""#)
        let indicators = CompiledIndicators([rule])
        XCTAssertTrue(indicators.problems.isEmpty, "\(indicators.problems.map(\.reason))")
        XCTAssertTrue(indicators.readsLaunchedByParent)
        XCTAssertFalse(Self.shippedIndicators.readsLaunchedByParent)
        var stamped = try appExec(pid: 606)
        var values = MessageValueCache()
        indicators.stamp(&stamped, values: &values)
        XCTAssertEqual(stamped.indicators?.hits.map(\.id), [], "Not yet launched by the launcher")
        let hold = hold(FakeLaunchServicesReader { pid, _ in self.launch(of: pid) })
        hold.hold(stamped, stampedWith: indicators)
        let sent = try XCTUnwrap(try sentExecs(1).first)
        withExtendedLifetime(hold) {}
        XCTAssertEqual(launchedByParent(of: sent)?.path, "/path/of/700")
        XCTAssertEqual(sent.indicators?.hits.map(\.id), [rule.id])
    }

    /// An exec past the hold's bound leaves at once, with its verdicts.
    func testVerdictsSurviveTheBound() throws {
        let reader = FakeLaunchServicesReader { pid, attempt in attempt == 0 ? nil : self.launch(of: pid) }
        let hold = hold(reader, maxHeld: 1)
        let (first, second) = (try appExec(pid: 606), try appExec(pid: 607))
        hold.hold(first)
        hold.hold(second)
        let sent = try sentExecs(2)
        XCTAssertEqual(sent.map(\.indicators), [first.indicators, second.indicators])
        XCTAssertEqual(launchedByParent(of: sent.last), .appJob(), "Not looked up")
    }

    /// Closing releases a held exec as it is, verdicts and all.
    func testVerdictsSurviveRelease() throws {
        let reader = WaitingLaunchServicesReader()
        defer { reader.open() }
        let hold = hold(reader)
        let stamped = try appExec(pid: 606)
        hold.hold(stamped)
        hold.close()
        XCTAssertEqual(try sentExecs(1).first?.indicators, stamped.indicators)
    }

    /// An exec stamped with indicators its budget couldn't decide keeps them, beside its verdicts, whether it's
    /// settled with Launch Services' answer or released as the lane closes.
    func testUndeterminedSurviveTheHold() throws {
        let settled = try undecidedAppExec(pid: 606)
        let settling = hold(FakeLaunchServicesReader { pid, _ in self.launch(of: pid) })
        settling.hold(settled)
        XCTAssertEqual(try sentExecs(1).count, 1)
        let reader = WaitingLaunchServicesReader()
        defer { reader.open() }
        let released = try undecidedAppExec(pid: 607), closing = hold(reader)
        closing.hold(released)
        closing.close()
        let sent = try sentExecs(2)
        XCTAssertEqual(sent.map(\.indicators_undetermined), [settled, released].map(\.indicators_undetermined))
        XCTAssertEqual(sent.map(\.indicators), [settled, released].map(\.indicators))
    }
}


// MARK: - Helpers
extension LaunchServicesHoldIndicatorTests {
    /// The target token of an app's exec: a user's process in audit session 100001.
    ///
    /// - Parameter pid: The app's pid. Its pid version is ten times that.
    /// - Returns: The token.
    static func target(_ pid: Int32) -> AuditToken {
        AuditToken(pid: pid, pidversion: pid * 10, asid: 100_001, auid: 501, euid: 501, ruid: 501, rgid: 20, egid: 20)
    }

    /// An app's exec as a lane builds it: Launch Services must say who launched it, so it's held, and it's stamped.
    ///
    /// - Parameter pid: The app's pid.
    /// - Returns: The event, with at least one verdict.
    /// - Throws: A failure when it matches nothing.
    func appExec(pid: Int32) throws -> Message {
        var message = try XCTUnwrap(exec)
        if case .exec(var event) = message.event {
            event.target.pid = pid
            event.target.audit_token = Self.target(pid)
            message.event = .exec(event)
        }
        message.setLaunchedByParent(.appJob())
        message.id = UUID()
        var values = MessageValueCache()
        Self.shippedIndicators.stamp(&message, values: &values)
        XCTAssertTrue(LaunchServicesHold.holds(message))
        XCTAssertFalse(try XCTUnwrap(message.indicators).hits.isEmpty)
        return message
    }

    /// An app's exec stamped with no scan budget, so every shipped exec rule that reads its values is undetermined.
    ///
    /// - Parameter pid: The app's pid.
    /// - Returns: The event, held for Launch Services, with undetermined indicators.
    /// - Throws: A failure when none is undetermined.
    func undecidedAppExec(pid: Int32) throws -> Message {
        var message = try appExec(pid: pid)
        var values = MessageValueCache()
        values.scan.limit = 0
        Self.shippedIndicators.stamp(&message, values: &values)
        XCTAssertTrue(LaunchServicesHold.holds(message))
        XCTAssertFalse(try XCTUnwrap(message.indicators_undetermined).entries.isEmpty)
        return message
    }

    /// A record of an app's launch by ``launcher``.
    ///
    /// - Parameter pid: The app's pid.
    /// - Returns: The record.
    func launch(of pid: pid_t) -> LaunchServicesRecord {
        LaunchServicesRecord(token: Self.target(pid), launchedByLaunchServices: true, hasParentASN: true,
                             parentToken: launcher)
    }

    /// A hold for the process lane that sends into ``emitted``.
    ///
    /// - Parameters:
    ///   - reader: The Launch Services reader.
    ///   - maxHeld: The most execs held at a time.
    /// - Returns: The hold.
    func hold(_ reader: LaunchServicesReading, maxHeld: Int = 64) -> LaunchServicesHold {
        let upgrader = LaunchedByParentUpgrader(reader: reader, delays: [0, 0.01]) { pid, _ in "/path/of/\(pid)" }
        return LaunchServicesHold(eventClass: .process, upgrader: upgrader, maxHeld: maxHeld, maxWait: 5,
                                  emit: emitted.append)
    }

    /// Wait for the hold to send execs, and read them as Mac Monitor decodes them.
    ///
    /// - Parameter count: How many.
    /// - Returns: The execs, in order.
    /// - Throws: A failure when fewer were sent in time, or the error decoding one.
    func sentExecs(_ count: Int) throws -> [Message] {
        XCTAssertTrue(waitUntil { emitted.all.count == count }, "\(emitted.all.count) events")
        return try emitted.all.map { try JSONDecoder().decode(Message.self, from: $0.json) }
    }

    /// - Parameter message: An exec.
    /// - Returns: Its launched-by parent.
    func launchedByParent(of message: Message?) -> LaunchedByParent? {
        guard case .exec(let exec) = message?.event else { return nil }
        return exec.launched_by_parent
    }
}
