//
//  LaunchServicesHoldSequenceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Sequences through the hold
/// Pins the sequences of the exec lane, whose events advance them as the Launch Services hold sends them: an app's
/// held exec with the launched-by parent it leaves with, and an event behind it after it, in Endpoint Security's
/// order. A step can read the launched-by parent, whether it starts the chain or completes it.
final class LaunchServicesHoldSequenceTests: XCTestCase {
    /// The process that asked Launch Services to launch the apps.
    private let launcher = LaunchServicesHoldIndicatorTests.target(700)
    /// Events the hold sent, in order.
    private let emitted = EmittedEvents()
    /// eslogger's exec of curl, which the apps' execs are made from.
    private var exec: Message!

    /// A step on an exec the launcher launched.
    private let launched = IndicatorSequence.Step(
        name: "launched", predicate: #"event.exec != nil AND event.exec.launched_by_parent.path == "/path/of/700""#)

    /// Read the exec, and make it curl's.
    ///
    /// - Throws: The error reading it.
    override func setUpWithError() throws {
        exec = try importRecord(try esloggerExec(parent: (1, 1), args: ["curl", "-sO", "https://example.com/x"]))
        guard case .exec(var event) = exec.event else { return XCTFail("Not an exec") }
        event.target.executable?.path = "/usr/bin/curl"
        exec.event = .exec(event)
    }

    /// An app the launcher launched, then its executable run again: the held exec's step reads the parent Launch
    /// Services names, and the exec behind it, which waited, completes the chain. Without Launch Services' answer
    /// nothing completes.
    func testAHeldExecStartsAChainWithItsSettledParent() throws {
        let again = IndicatorSequence.Step(name: "again", predicate: "event.exec != nil", join: [
            IndicatorSequence.Join(field: "event.exec.target.executable.path", step: "launched",
                                   stepField: "event.exec.target.executable.path"),
        ])
        let sequence = sequenceIndicator(IndicatorSequence(order: .ordered, within: 5, steps: [launched, again]))
        for (round, answers) in [true, false].enumerated() {
            let compiled = CompiledIndicators([sequence]), chains = SessionChains(for: compiled)
            XCTAssertTrue(compiled.problems.isEmpty, "\(compiled.problems.map(\.reason))")
            let gate = DispatchSemaphore(value: 0)
            let hold = hold(FakeLaunchServicesReader { pid, _ in
                gate.wait()
                return answers ? self.launch(of: pid) : nil
            })
            let (held, heldSteps) = appExec(pid: 606, stampedWith: compiled)
            let (behind, behindSteps) = appExec(pid: 607, at: 1, stampedWith: compiled)
            hold.hold(held, stampedWith: compiled, chains: chains, steps: heldSteps)
            hold.submit(behind, stampedWith: compiled, chains: chains, steps: behindSteps)
            XCTAssertEqual(emitted.all.count, 2 * round, "The exec behind waits")
            gate.signal()
            let sent = try sentExecs(2 * round + 2).suffix(2)
            XCTAssertEqual(sent.map { hits(sequence, $0) }, [false, answers], "Launch Services answers: \(answers)")
            XCTAssertEqual(compiled.openChains, 0, "The session's chains, not the set's")
        }
    }

    /// An exec run, then an app the launcher launched from the same executable: the held exec completes the chain
    /// once Launch Services names its parent, and it's the one tagged.
    func testAHeldExecCompletesAChainWithItsSettledParent() throws {
        let run = IndicatorSequence.Step(name: "run", predicate: "event.exec != nil")
        let after = IndicatorSequence.Step(name: "launched", predicate: launched.predicate, join: [
            IndicatorSequence.Join(field: "event.exec.target.executable.path", step: "run",
                                   stepField: "event.exec.target.executable.path"),
        ])
        let sequence = sequenceIndicator(IndicatorSequence(order: .ordered, within: 5, steps: [run, after]))
        let compiled = CompiledIndicators([sequence]), chains = SessionChains(for: compiled)
        let hold = hold(FakeLaunchServicesReader { pid, _ in self.launch(of: pid) })
        let (first, firstSteps) = appExec(pid: 605, stampedWith: compiled)
        let (held, heldSteps) = appExec(pid: 606, at: 1, stampedWith: compiled)
        hold.submit(first, stampedWith: compiled, chains: chains, steps: firstSteps)
        hold.hold(held, stampedWith: compiled, chains: chains, steps: heldSteps)
        let sent = try sentExecs(2)
        XCTAssertEqual(sent.map { hits(sequence, $0) }, [false, true])
    }
}


// MARK: - Helpers
extension LaunchServicesHoldSequenceTests {
    /// An app's exec as the exec lane builds it: held for Launch Services, and stamped deferring its sequence steps.
    ///
    /// - Parameters:
    ///   - pid: The app's pid.
    ///   - time: Its time, in seconds after the eslogger exec's.
    ///   - indicators: The set to stamp it with.
    /// - Returns: The event, and the steps its stamp left for the hold.
    private func appExec(pid: Int32, at time: Double = 0,
                         stampedWith indicators: CompiledIndicators) -> (Message, ContiguousArray<Int32>) {
        var message: Message = exec
        if case .exec(var event) = message.event {
            event.target.pid = pid
            event.target.audit_token = LaunchServicesHoldIndicatorTests.target(pid)
            message.event = .exec(event)
        }
        message.setLaunchedByParent(.appJob())
        message.id = UUID()
        message.message_darwin_time += time
        var values = MessageValueCache()
        let steps = indicators.stamp(&message, values: &values, deferringSteps: true)
        XCTAssertTrue(LaunchServicesHold.holds(message))
        return (message, steps)
    }

    /// - Parameters:
    ///   - sequence: A sequence's indicator.
    ///   - message: An event the hold sent.
    /// - Returns: Does it carry the sequence's hit?
    private func hits(_ sequence: Indicator, _ message: Message) -> Bool {
        message.indicators?.hits.contains { $0.id == sequence.id } == true
    }

    /// A record of an app's launch by ``launcher``.
    ///
    /// - Parameter pid: The app's pid.
    /// - Returns: The record.
    private func launch(of pid: pid_t) -> LaunchServicesRecord {
        LaunchServicesRecord(token: LaunchServicesHoldIndicatorTests.target(pid), launchedByLaunchServices: true,
                             hasParentASN: true, parentToken: launcher)
    }

    /// A hold for the process lane that sends into ``emitted``, naming each launcher's executable by its pid.
    ///
    /// - Parameter reader: The Launch Services reader.
    /// - Returns: The hold.
    private func hold(_ reader: LaunchServicesReading) -> LaunchServicesHold {
        let upgrader = LaunchedByParentUpgrader(reader: reader, delays: [0]) { pid, _ in "/path/of/\(pid)" }
        return LaunchServicesHold(eventClass: .process, upgrader: upgrader, maxWait: 5, emit: emitted.append)
    }

    /// Wait for the hold to send events, and read them as Mac Monitor decodes them.
    ///
    /// - Parameter count: How many.
    /// - Returns: The events, in order.
    /// - Throws: A failure when fewer were sent in time, or the error decoding one.
    private func sentExecs(_ count: Int) throws -> [Message] {
        XCTAssertTrue(waitUntil { emitted.all.count == count }, "\(emitted.all.count) events")
        return try emitted.all.map { try JSONDecoder().decode(Message.self, from: $0.json) }
    }
}
