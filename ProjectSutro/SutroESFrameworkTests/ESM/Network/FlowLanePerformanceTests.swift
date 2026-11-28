//
//  FlowLanePerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The network lane's cost
/// Times what a session's network lane does on the client's delivery queue for one flow record: build its event,
/// stamp it, encode it and emit it. Without indicators, and with the shipped ones.
final class FlowLanePerformanceTests: PerformanceTestCase {
    /// How many records each sample handles: half openings, half closes.
    private let records = 2_000

    /// A lane recording both flow events, whose events are dropped as they're emitted.
    ///
    /// - Parameter indicators: The indicators to stamp, or `nil`.
    /// - Returns: The lane.
    private func makeLane(indicators: CompiledIndicators?) -> FlowLane {
        let lane = FlowLane(client: .fake(), sensorID: "SENSOR", indicators: indicators, chains: nil,
                            mutes: FlowMutes(MuteList.shippedDefault(for: nil)), mutesSelf: true,
                            recordsURLPaths: true, lineage: nil, snapshots: nil, macOS: "27.2 (Build 26B123)",
                            sipStatus: .disabled, bootSession: nil, emit: { _ in })
        lane.setSubscribed(Set(MacMonitorEvent.allCases))
        lane.setRecording(true)
        return lane
    }

    /// Hand the lane records, and check every one was built.
    ///
    /// - Parameter lane: The lane.
    /// - Throws: ``BenchmarkFailure`` when one wasn't.
    private func handle(_ lane: FlowLane) throws {
        let flows = [SyntheticFlows.record(.opened), SyntheticFlows.record(.closed)]
        let before = lane.statistics().records
        for index in 0..<records { lane.handle(flows[index & 1]) }
        let statistics = lane.statistics()
        guard statistics.records - before == UInt64(records), statistics.serializationFailures == 0 else {
            throw BenchmarkFailure("Every record built and encoded")
        }
    }

    /// One record without indicators.
    func testHandlingARecord() throws {
        try benchmark("network.lane.record", unit: "record", operations: records,
                      setUp: { makeLane(indicators: nil) }, handle)
    }

    /// One record stamped with the shipped indicators.
    func testHandlingARecordWithIndicators() throws {
        let shipped = Self.shippedIndicators
        try benchmark("network.lane.record.indicators", unit: "record", operations: records,
                      setUp: { makeLane(indicators: shipped) }, handle)
    }
}
