//
//  StreamPlanTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Stream plans
/// Pins what a Security Extension agrees to stream: NOTIFY events Mac Monitor models, each once, in order, and never
/// more names than ``StreamPlan/maximumEvents``.
final class StreamPlanTests: XCTestCase {
    /// No events, from a 3.0.0 request without field filters, means 3.0.0's defaults: never close, which it would
    /// stream unfiltered. The saved mutes apply unless the request says otherwise.
    func testNoEventsMeansTheDefaults() throws {
        let plan = try StreamPlan(StreamOptions())
        XCTAssertEqual(plan.events, defaultEventSubscriptionsWithoutFieldFilters)
        XCTAssertFalse(plan.events.contains(ES_EVENT_TYPE_NOTIFY_CLOSE))
        XCTAssertNil(plan.fieldFilters)
        XCTAssertTrue(plan.appliesSavedMutes)
        XCTAssertFalse(try StreamPlan(StreamOptions(appliesSavedMutes: false)).appliesSavedMutes)
    }
    
    /// A stream scans written files only when its request asks, and a request from a `macmonitor` before 3.3.0,
    /// which never names it, doesn't.
    func testScanningIsAskedFor() throws {
        XCTAssertFalse(try StreamPlan(StreamOptions()).scansWrittenFiles)
        XCTAssertTrue(try StreamPlan(StreamOptions(scansWrittenFiles: true)).scansWrittenFiles)
        let older = Data(#"{"events":[],"appliesSavedMutes":true}"#.utf8)
        XCTAssertFalse(try JSONDecoder().decode(StreamOptions.self, from: older).scansWrittenFiles)
        let asked = try JSONEncoder().encode(StreamOptions(scansWrittenFiles: true))
        XCTAssertTrue(try JSONDecoder().decode(StreamOptions.self, from: asked).scansWrittenFiles)
    }

    /// A stream may name the two flow events, which no default includes. URL paths are kept unless the request
    /// says not to, and a request from a `macmonitor` before 3.3.0, which never names them, keeps them.
    func testFlowsAreNamedAndKeepTheirURLPaths() throws {
        let plan = try StreamPlan(StreamOptions(events: ["new_flow", "flow_closed", "ES_EVENT_TYPE_NOTIFY_EXEC"]))
        XCTAssertEqual(plan.events, [MacMonitorEvent.new_flow.type, MacMonitorEvent.flow_closed.type,
                                     ES_EVENT_TYPE_NOTIFY_EXEC])
        XCTAssertFalse(try StreamPlan(StreamOptions()).events.contains { MacMonitorEvent($0) != nil })
        XCTAssertTrue(plan.recordsURLPaths)
        XCTAssertFalse(try StreamPlan(StreamOptions(recordsURLPaths: false)).recordsURLPaths)
        let older = Data(#"{"events":[],"appliesSavedMutes":true}"#.utf8)
        XCTAssertTrue(try JSONDecoder().decode(StreamOptions.self, from: older).recordsURLPaths)
        let asked = try JSONEncoder().encode(StreamOptions(recordsURLPaths: false))
        XCTAssertFalse(try JSONDecoder().decode(StreamOptions.self, from: asked).recordsURLPaths)
    }

    /// Each event is kept once, in the order it was first named.
    func testDuplicatesAreDroppedInOrder() throws {
        let names = ["ES_EVENT_TYPE_NOTIFY_FORK", "ES_EVENT_TYPE_NOTIFY_EXEC", "ES_EVENT_TYPE_NOTIFY_FORK"]
        let plan = try StreamPlan(StreamOptions(events: names))
        XCTAssertEqual(plan.events, [ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXEC])
    }
    
    /// Every event Mac Monitor models can be streamed.
    func testEverySupportedEventCanBeStreamed() throws {
        let names = supportedEvents.map { eventTypeToString(from: $0) }
        XCTAssertEqual(try StreamPlan(StreamOptions(events: names)).events, supportedEvents)
    }
    
    /// AUTH events, `ES_EVENT_TYPE_LAST`, NOTIFY events Mac Monitor doesn't model, short names, and unknown names
    /// are refused, and so are more than ``StreamPlan/maximumEvents`` names.
    func testWhatIsRefused() {
        for name in ["ES_EVENT_TYPE_AUTH_EXEC", "ES_EVENT_TYPE_LAST", "ES_EVENT_TYPE_NOTIFY_KEXTLOAD", "exec", "",
                     "ES_EVENT_TYPE_NOTIFY_EXEC "] {
            let error = thrown(XPCRequestError.self) { try StreamPlan(StreamOptions(events: [name])) }
            XCTAssertEqual(error?.status(as: StreamReply.Status.self), .invalid, name)
        }
        let tooMany = Array(repeating: "ES_EVENT_TYPE_NOTIFY_EXEC", count: StreamPlan.maximumEvents + 1)
        XCTAssertThrowsError(try StreamPlan(StreamOptions(events: tooMany)))
        XCTAssertNoThrow(try StreamPlan(StreamOptions(events: Array(tooMany.dropLast()))))
    }
    
    /// With the field filters named, no events means every default, close included, modified-only. No filters at
    /// all means the same events, every close streamed.
    func testFieldFiltersWithTheDefaults() throws {
        let filtered = try StreamPlan(StreamOptions(fieldFilters: [FieldFilter.modifiedCloses.rawValue]))
        XCTAssertEqual(filtered.events, defaultEventSubscriptions)
        XCTAssertTrue(filtered.events.contains(ES_EVENT_TYPE_NOTIFY_CLOSE))
        XCTAssertEqual(filtered.fieldFilters, [.modifiedCloses])
        let unfiltered = try StreamPlan(StreamOptions(fieldFilters: []))
        XCTAssertEqual(unfiltered.events, defaultEventSubscriptions)
        XCTAssertEqual(unfiltered.fieldFilters, [])
    }
    
    /// A filter on an event the stream doesn't subscribe to is dropped: it would check nothing.
    func testFiltersOnlyApplyToSubscribedEvents() throws {
        let options = StreamOptions(events: ["ES_EVENT_TYPE_NOTIFY_EXEC"],
                                    fieldFilters: [FieldFilter.modifiedCloses.rawValue])
        XCTAssertEqual(try StreamPlan(options).fieldFilters, [])
        let closes = StreamOptions(events: ["ES_EVENT_TYPE_NOTIFY_CLOSE"],
                                   fieldFilters: [FieldFilter.modifiedCloses.rawValue])
        XCTAssertEqual(try StreamPlan(closes).fieldFilters, [.modifiedCloses])
    }
    
    /// A filter this build doesn't know comes from a newer `macmonitor`: unsupported. Two filters on one event, or
    /// more names than ``StreamPlan/maximumEvents``, are invalid. Naming one filter twice is the same as once.
    func testWhatFieldFiltersAreRefused() {
        let unknown = thrown(XPCRequestError.self) {
            try StreamPlan(StreamOptions(fieldFilters: ["ES_EVENT_TYPE_NOTIFY_CLOSE.was_mapped_writable"]))
        }
        XCTAssertEqual(unknown?.status(as: StreamReply.Status.self), .unsupported)
        XCTAssertEqual(unknown?.description, "ES_EVENT_TYPE_NOTIFY_CLOSE.was_mapped_writable isn't a field filter "
                       + "this Security Extension knows. Open Mac Monitor to finish updating.")
        let close = ES_EVENT_TYPE_NOTIFY_CLOSE
        XCTAssertEqual(try StreamPlan.fieldFilters(named: Array(repeating: FieldFilter.modifiedCloses.rawValue,
                                                                count: 2), over: [close]), [.modifiedCloses])
        let tooMany = Array(repeating: FieldFilter.modifiedCloses.rawValue, count: StreamPlan.maximumEvents + 1)
        let error = thrown(XPCRequestError.self) { try StreamPlan(StreamOptions(fieldFilters: tooMany)) }
        XCTAssertEqual(error?.status(as: StreamReply.Status.self), .invalid)
    }
}
