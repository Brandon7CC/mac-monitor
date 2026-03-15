//
//  StressTestConfigurationTests.swift
//  ProjectSutroUITests
//
//  Guards the stress test harness itself (threshold and suite configuration),
//  so CI signal remains stable as tuning evolves.
//

import XCTest

final class StressTestConfigurationTests: XCTestCase {
    func testGuardrailThresholdsAreLooserThanTargets() {
        let guardrail = PerformanceThresholds.guardrail
        let target = PerformanceThresholds.target

        XCTAssertGreaterThanOrEqual(guardrail.p95LatencyMs, target.p95LatencyMs)
        XCTAssertGreaterThanOrEqual(guardrail.p99LatencyMs, target.p99LatencyMs)
        XCTAssertGreaterThanOrEqual(guardrail.maxStallMs, target.maxStallMs)
        XCTAssertGreaterThanOrEqual(guardrail.maxDroppedFrames30fpsPercent, target.maxDroppedFrames30fpsPercent)
        XCTAssertLessThanOrEqual(guardrail.minEffectiveRatePercent, target.minEffectiveRatePercent)
        XCTAssertGreaterThanOrEqual(guardrail.maxResidentBytesPerInsertedEvent, target.maxResidentBytesPerInsertedEvent)
    }

    func testGuardrailThresholdsAreReasonable() {
        let guardrail = PerformanceThresholds.guardrail

        XCTAssertGreaterThan(guardrail.p95LatencyMs, 0)
        XCTAssertGreaterThan(guardrail.p99LatencyMs, 0)
        XCTAssertGreaterThan(guardrail.maxStallMs, 0)
        XCTAssertGreaterThanOrEqual(guardrail.maxDroppedFrames30fpsPercent, 0)
        XCTAssertLessThanOrEqual(guardrail.maxDroppedFrames30fpsPercent, 100)
        XCTAssertGreaterThanOrEqual(guardrail.minEffectiveRatePercent, 0)
        XCTAssertLessThanOrEqual(guardrail.minEffectiveRatePercent, 100)
        XCTAssertGreaterThan(guardrail.maxResidentBytesPerInsertedEvent, 0)
    }
}
