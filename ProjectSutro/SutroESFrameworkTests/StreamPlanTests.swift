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
    /// No events means Mac Monitor's defaults; the saved mutes apply unless the request says otherwise.
    ///
    /// - Throws: ``XPCRequestError`` if the options are refused.
    func testNoEventsMeansTheDefaults() throws {
        let plan = try StreamPlan(StreamOptions())
        XCTAssertEqual(plan.events, defaultEventSubscriptions)
        XCTAssertTrue(plan.appliesSavedMutes)
        XCTAssertFalse(try StreamPlan(StreamOptions(appliesSavedMutes: false)).appliesSavedMutes)
    }
    
    /// Each event is kept once, in the order it was first named.
    ///
    /// - Throws: ``XPCRequestError`` if the options are refused.
    func testDuplicatesAreDroppedInOrder() throws {
        let names = ["ES_EVENT_TYPE_NOTIFY_FORK", "ES_EVENT_TYPE_NOTIFY_EXEC", "ES_EVENT_TYPE_NOTIFY_FORK"]
        let plan = try StreamPlan(StreamOptions(events: names))
        XCTAssertEqual(plan.events, [ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXEC])
        XCTAssertEqual(plan.eventNames, ["ES_EVENT_TYPE_NOTIFY_FORK", "ES_EVENT_TYPE_NOTIFY_EXEC"])
    }
    
    /// Every event Mac Monitor models can be streamed.
    ///
    /// - Throws: ``XPCRequestError`` if the options are refused.
    func testEverySupportedEventCanBeStreamed() throws {
        let names = supportedEvents.map { eventTypeToString(from: $0) }
        XCTAssertEqual(try StreamPlan(StreamOptions(events: names)).events, supportedEvents)
    }
    
    /// AUTH events, `ES_EVENT_TYPE_LAST`, NOTIFY events Mac Monitor doesn't model, short names, and unknown names
    /// are refused, and so are more than ``StreamPlan/maximumEvents`` names.
    func testWhatIsRefused() {
        for name in ["ES_EVENT_TYPE_AUTH_EXEC", "ES_EVENT_TYPE_LAST", "ES_EVENT_TYPE_NOTIFY_KEXTLOAD", "exec", "",
                     "ES_EVENT_TYPE_NOTIFY_EXEC "] {
            XCTAssertThrowsError(try StreamPlan(StreamOptions(events: [name])), name) { error in
                XCTAssertEqual((error as? XPCRequestError)?.status(as: StreamReply.Status.self), .invalid, name)
            }
        }
        let tooMany = Array(repeating: "ES_EVENT_TYPE_NOTIFY_EXEC", count: StreamPlan.maximumEvents + 1)
        XCTAssertThrowsError(try StreamPlan(StreamOptions(events: tooMany)))
        XCTAssertNoThrow(try StreamPlan(StreamOptions(events: Array(tooMany.dropLast()))))
    }
}
