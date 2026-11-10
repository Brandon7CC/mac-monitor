//
//  MessageSerializerIndicatorPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Serializing with indicators
/// Times what stamping indicators adds to a capture lane's work per event: `MessageSerializer.serializeEvent` on the
/// events `capture.serialize.*` times (``MessageSerializerPerformanceTests``), on a lane with an empty set, the
/// shipped indicators, and 500 rules of the event's type. Compare each with `capture.serialize.<event>` from the same
/// run, or from the `-O` baseline. `<shipped>` is how many indicators Mac Monitor ships.
///
/// | Benchmark | Budget over `capture.serialize.<event>` |
/// |---|---|
/// | `capture.serialize.<event>.indicators.0` | none: reported |
/// | `capture.serialize.<event>.indicators.<shipped>` | ≤ 2% |
/// | `capture.serialize.<event>.indicators.500` | ≤ 15% |
/// | `capture.serialize.{close,open}.indicators.<shipped>.record` | reported: one walk of the event's encoding |
/// | `capture.serialize.open.indicators.<shipped>.record.guarded` | ≤ 2%: no walk |
///
/// Execs can't go through the serializer in the tests (``RawMessageFixture``): `indicators.evaluate.exec.*`
/// (``IndicatorPerformanceTests``) and `capture.encode.exec` time them.
final class MessageSerializerIndicatorPerformanceTests: PerformanceTestCase {
    /// Messages per sample.
    private static let events = 2_000

    /// Close, no rules.
    func testCloseNoRules() throws { try run(.close, .none) }
    /// Close, the shipped rules.
    func testCloseShipped() throws { try run(.close, .shipped) }
    /// Close, 500 close rules.
    func testClose500() throws { try run(.close, .distinct(500)) }
    /// Create, no rules.
    func testCreateNoRules() throws { try run(.create, .none) }
    /// Create, the shipped rules.
    func testCreateShipped() throws { try run(.create, .shipped) }
    /// Create, 500 create rules.
    func testCreate500() throws { try run(.create, .distinct(500)) }
    /// Open, no rules.
    func testOpenNoRules() throws { try run(.open, .none) }
    /// Open, the shipped rules.
    func testOpenShipped() throws { try run(.open, .shipped) }
    /// Open, 500 open rules.
    func testOpen500() throws { try run(.open, .distinct(500)) }
    /// Mmap, no rules.
    func testMmapNoRules() throws { try run(.mmap, .none) }
    /// Mmap, the shipped rules.
    func testMmapShipped() throws { try run(.mmap, .shipped) }
    /// Mmap, 500 mmap rules.
    func testMmap500() throws { try run(.mmap, .distinct(500)) }
    /// Close, the shipped rules and two on record fields.
    func testCloseRecordFields() throws { try run(.close, .recordFields) }
    /// Open, the shipped rules and two on record fields.
    func testOpenRecordFields() throws { try run(.open, .recordFields) }
    /// Open, the shipped rules and one on a record field guarded by a path.
    func testOpenGuardedRecordField() throws { try run(.open, .guardedRecordField) }
}


// MARK: - Measuring
extension MessageSerializerIndicatorPerformanceTests {
    /// - Parameter event: A capture benchmark's event.
    /// - Returns: Its type.
    static func type(of event: CaptureBenchmarkEvent) -> es_event_type_t {
        switch event {
        case .close: ES_EVENT_TYPE_NOTIFY_CLOSE
        case .create: ES_EVENT_TYPE_NOTIFY_CREATE
        case .mmap: ES_EVENT_TYPE_NOTIFY_MMAP
        case .fork: ES_EVENT_TYPE_NOTIFY_FORK
        case .exit: ES_EVENT_TYPE_NOTIFY_EXIT
        case .open, .openByThirdParty: ES_EVENT_TYPE_NOTIFY_OPEN
        }
    }

    /// Serialize an event's message on a lane with a set, then print how many rules of its type the set has, how many
    /// its index has it evaluated against, and how many it matches.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - rules: The lane's rules.
    /// - Throws: ``BenchmarkFailure`` if a message isn't encoded or isn't stamped, or the error writing the results.
    func run(_ event: CaptureBenchmarkEvent, _ rules: IndicatorPerformanceTests.Rules) throws {
        let type = Self.type(of: event)
        let indicators = try rules.indicators(for: type, in: self)
        let count = switch rules {
        case .recordFields: "\(Indicator.defaults.count).record"
        case .guardedRecordField: "\(Indicator.defaults.count).record.guarded"
        default: "\(indicators.count)"
        }
        let compiled = CompiledIndicators(indicators)
        let fixture = try rawMessage(for: event)
        let serializer = MessageSerializer(processPath: { _, _ in "/bin/zsh" })
        let lane = LaneContext(eventClass: event.eventClass, sensorID: "SENSOR", encoder: StreamingJSONEncoder(),
                               indicators: compiled)
        let name = "capture.serialize.\(event.rawValue).indicators.\(count)"
        try benchmark(name, operations: Self.events) {
            for _ in 0..<Self.events {
                guard case .json = serializer.serializeEvent(fixture.raw, in: lane) else {
                    throw BenchmarkFailure("\(event) wasn't encoded")
                }
            }
        }
        let json = try XCTUnwrap(serializer.serialize(fixture.raw, in: lane))
        let message = try JSONDecoder().decode(Message.self, from: json)
        let hits = try XCTUnwrap(message.indicators, "Not stamped").hits
        var values = MessageValueCache()
        print("[performance] \(name): \(compiled.candidates(forType: Int(type.rawValue))) rules of its type, "
              + "\(compiled.candidates(for: message, values: &values).count) evaluated, \(hits.count) hits/event")
    }
}
