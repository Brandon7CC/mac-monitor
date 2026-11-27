//
//  IndicatorCompilerNetworkTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Network flows' types
/// Pins how ``IndicatorCompiler`` takes a network flow's type: a payload test compiles, and an `es_event_type`
/// comparison with a flow's name is refused with the reason, wherever it sits, since a flow's record has no
/// `es_event_type`.
final class IndicatorCompilerNetworkTests: XCTestCase {
    /// A payload test compiles to the flow's type, and its program says so as a payload test.
    func testAPayloadTestCompiles() throws {
        let rule = try IndicatorCompiler.compile(#"event.new_flow != nil AND event.new_flow.url BEGINSWITH "https""#)
            .get()
        XCTAssertEqual(rule.types, [Int(MacMonitorEvent.new_flow.rawValue)])
        let both = try IndicatorCompiler.compile("event.new_flow != nil OR event.flow_closed != nil").get()
        XCTAssertEqual(both.types, MacMonitorEvent.allCases.map { Int($0.rawValue) })
    }

    /// `es_event_type == "new_flow"` is refused as no event type, alone and under `AND`, `OR` and `NOT`, and the
    /// reason says what to write instead.
    func testComparingTheTypeIsRefused() {
        let comparisons = [#"es_event_type == "new_flow""#, #"es_event_type IN {"new_flow", "flow_closed"}"#,
                           #"es_event_type == "new_flow" AND event.new_flow.remote_endpoint.port == 443"#,
                           #"es_event_type == "new_flow" OR event.exec != nil"#,
                           #"event.exec != nil AND NOT es_event_type == "new_flow""#]
        for source in comparisons {
            XCTAssertEqual(IndicatorCompiler.problem(with: source), .noEventType("new_flow"), source)
        }
        XCTAssertEqual(IndicatorCompiler.problem(with: #"es_event_type == "flow_closed""#),
                       .noEventType("flow_closed"))
        XCTAssertEqual(SensorProblem.noEventType("new_flow").description,
                       "new_flow records have no es_event_type. Use event.new_flow != nil.")
    }

    /// A program that checks a flow's type is written as its payload test, beside an Endpoint Security type's
    /// comparison, never as an `es_event_type` comparison a flow's record can't pass.
    func testProgramsDescribeAFlowsTypeAsItsPayload() throws {
        let source = #"(event.new_flow != nil AND event.new_flow.remote_endpoint.port == 443) OR "#
            + #"(event.exec != nil AND target_path == "/bin/sh")"#
        let description = try IndicatorCompiler.compile(source).get().program.description
        XCTAssertTrue(description.contains("event.new_flow != nil"), description)
        XCTAssertTrue(description.contains(#"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#), description)
        XCTAssertFalse(description.contains(#""new_flow""#), description)
        let reread = try IndicatorCompiler.compile(description).get()
        XCTAssertEqual(reread.types, try IndicatorCompiler.compile(source).get().types)
    }
}
