//
//  CompiledIndicatorsNetworkTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Indicators on network flows
/// Pins the Security Extension's indicators on network flows: a rule on a flow's type is kept and matches, reads
/// the flow's record as it's written, and a sequence treats a flow as on a lane of its own.
final class CompiledIndicatorsNetworkTests: XCTestCase {
    /// A flow that opened, and one that closed.
    private let opened = SyntheticFlows.message(SyntheticFlows.record(.opened))
    private let closed = SyntheticFlows.message(SyntheticFlows.record(.closed))

    /// - Parameter predicate: Its predicate.
    /// - Returns: An indicator of someone's own.
    private func indicator(_ predicate: String) -> Indicator {
        Indicator(name: "Test", description: "", symbol: "star", color: .blue, predicate: predicate)
    }

    /// - Parameters:
    ///   - predicate: A rule.
    ///   - message: An event.
    /// - Returns: Does the rule match the event?
    private func matches(_ predicate: String, _ message: Message) -> Bool {
        var values = MessageValueCache()
        return !CompiledIndicators([indicator(predicate)]).hits(for: message, values: &values).isEmpty
    }

    /// A rule on a flow's type is kept on that type, and matches its flows only.
    func testARuleOnAFlowIsKeptAndMatches() throws {
        let rule = #"event.new_flow != nil AND event.new_flow.remote_endpoint.port == 443"#
        let compiled = CompiledIndicators([indicator(rule)])
        XCTAssertEqual(compiled.problems.count, 0)
        XCTAssertTrue(matches(rule, opened))
        XCTAssertFalse(matches(rule, closed))
        XCTAssertFalse(matches(rule, try XCTUnwrap(SyntheticCorpus.records().first).message))
        XCTAssertTrue(matches(#"event.flow_closed != nil AND event.flow_closed.bytes_inbound_count > 1000"#, closed))
        XCTAssertTrue(matches(#"event.new_flow != nil AND event.new_flow.remote_hostname ENDSWITH "wikipedia.org""#
                              + #" AND process.executable.name == "nscurl""#, opened))
    }

    /// A rule reads a flow's remote address scope, as N1 in the indicators repository does with `NOT ... IN`.
    func testARuleReadsTheAddressScope() {
        let local = #"NOT event.new_flow.remote_address_scope IN {"private", "shared", "link_local", "loopback"}"#
        XCTAssertTrue(matches(#"event.new_flow != nil AND event.new_flow.remote_address_scope == "public""#, opened))
        XCTAssertTrue(matches("event.new_flow != nil AND " + local, opened))
        XCTAssertTrue(matches(#"event.flow_closed != nil AND event.flow_closed.remote_address_scope == "public""#,
                              closed))
        XCTAssertFalse(matches(#"event.new_flow != nil AND event.new_flow.remote_address_scope == "private""#, opened))
    }

    /// A rule reads a flow's process as its record writes it: no platform binary flag, and a code signing type only
    /// when it's known.
    func testRulesReadTheRecordsProcess() {
        XCTAssertTrue(matches(#"event.new_flow != nil AND process.is_platform_binary == nil"#, opened))
        XCTAssertTrue(matches(#"event.new_flow != nil AND process.codesigning_type == "PLATFORM""#, opened))
        let reaped = SyntheticFlows.message(SyntheticFlows.record(.opened,
                                                                  process: SyntheticFlows.process(state: .reaped)))
        XCTAssertTrue(matches(#"event.new_flow != nil AND process.codesigning_type == nil"#, reaped))
        XCTAssertTrue(matches(#"event.new_flow != nil AND process.ppid == nil"#, reaped))
        XCTAssertTrue(matches(#"event.new_flow != nil AND process.ppid == 512"#, opened))
    }

    /// An exec, then a connect by the process it started, within 5 seconds.
    private let runThenConnect: Indicator = {
        let run = IndicatorSequence.Step(name: "run", predicate: "event.exec != nil")
        let connect = IndicatorSequence.Step(
            name: "connect", predicate: "event.new_flow != nil",
            join: [IndicatorSequence.Join(field: "process.audit_token.pid", step: "run",
                                          stepField: "event.exec.target.audit_token.pid")])
        return Indicator(name: "Sequence", description: "", symbol: "star", color: .blue,
                         rule: .sequence(IndicatorSequence(order: .ordered, within: 5, steps: [run, connect])))
    }()

    /// - Parameter time: When it happened.
    /// - Returns: An exec that starts the flows' process, pid 753.
    private func flowsExec(at time: Date) throws -> Message {
        var exec = try XCTUnwrap(SyntheticCorpus.records().map(\.message).first { $0.event.exec != nil })
        if case .exec(var event) = exec.event {
            event.target.audit_token?.pid = 753
            exec.event = .exec(event)
        }
        exec.message_darwin_time = time
        return exec
    }

    /// An exec, then a flow of the process it starts: the flow's lane is another's, so it may come first, and the
    /// exec completes the chain as it comes. Two flow steps are one lane, in time order.
    func testAFlowAfterAnExecMayArriveEarly() throws {
        let compiled = CompiledIndicators([runThenConnect])
        XCTAssertEqual(compiled.sequences.first?.table.program.arrivesEarly, [false, true])
        let exec = try flowsExec(at: opened.message_darwin_time - 1)
        XCTAssertEqual(matchingLines(compiled, [opened, exec], matching: runThenConnect.id), [2])

        let close = IndicatorSequence.Step(
            name: "close", predicate: "event.flow_closed != nil",
            join: [IndicatorSequence.Join(field: "event.flow_closed.identifier", step: "open",
                                          stepField: "event.new_flow.identifier")])
        let open = IndicatorSequence.Step(name: "open", predicate: "event.new_flow != nil")
        let flows = sequenceIndicator(IndicatorSequence(order: .ordered, within: 5, steps: [open, close]))
        let both = CompiledIndicators([flows])
        XCTAssertEqual(both.sequences.first?.table.program.arrivesEarly, [false, false])
        XCTAssertEqual(matchingLines(both, [opened, moved(closed, by: 1)], matching: flows.id), [2])
    }

    /// A flow seen more than ``SequenceChains/clockStep`` after its socket was made is on its connect's time, not its
    /// socket's: the exec a second before it completes the chain, and no chain is forgotten.
    func testAFlowLongAfterItsSocketKeepsTheChains() throws {
        let late = SyntheticFlows.message(SyntheticFlows.record(.opened, start: SyntheticFlows.wall - 400_000_000_000))
        let exec = try flowsExec(at: Date(timeIntervalSince1970: Double(SyntheticFlows.wall) / 1e9 - 1))
        let compiled = CompiledIndicators([runThenConnect])
        XCTAssertEqual(matchingLines(compiled, [exec, late], matching: runThenConnect.id), [2])
        XCTAssertEqual(compiled.sequences.first?.table.clockResets, 0)
    }
}
