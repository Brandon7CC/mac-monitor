//
//  PathMuteTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Path mutes
/// Pins path mutes as values: Mac Monitor's default set flattened to one mute per path, and mutes read from the XPC
/// contract's names.
final class PathMuteTests: XCTestCase {
    /// Every path of every default rule becomes one mute: event-specific ones first, each scoped to its one event,
    /// then global ones, scoped to none.
    func testDefaultMuteSetFlattensEveryRule() {
        let muteSet = MuteSet.default
        let mutes = muteSet.pathMutes
        let scopedCount = muteSet.eventSpecificRules.map { $0.paths.count }.reduce(0, +)
        let globalCount = muteSet.globalRules.map { $0.paths.count }.reduce(0, +)
        XCTAssertEqual(mutes.count, scopedCount + globalCount)
        XCTAssertGreaterThan(scopedCount, 0)
        XCTAssertGreaterThan(globalCount, 0)
        
        let scoped = Array(mutes.prefix(scopedCount))
        let expected = muteSet.eventSpecificRules.flatMap { rule in rule.paths.map { (rule, $0) } }
        for (mute, (rule, path)) in zip(scoped, expected) {
            XCTAssertEqual(mute, PathMute(path: path, type: rule.muteType, events: [rule.eventType]))
        }
        for mute in mutes.suffix(globalCount) {
            XCTAssertTrue(mute.events.isEmpty, mute.path)
        }
        XCTAssertEqual(mutes.last, PathMute(path: muteSet.globalRules.last?.paths.last ?? "",
                                            type: muteSet.globalRules.last?.pathType ?? ES_MUTE_PATH_TYPE_PREFIX))
    }
    
    /// The XPC contract's names become the mute they name; no event names means every event.
    func testXPCNamesBecomeAMute() {
        XCTAssertEqual(PathMute(path: "/tmp/x", typeName: "ES_MUTE_PATH_TYPE_TARGET_PREFIX",
                                eventNames: ["ES_EVENT_TYPE_NOTIFY_OPEN", "ES_EVENT_TYPE_NOTIFY_CLOSE"]),
                       PathMute(path: "/tmp/x", type: ES_MUTE_PATH_TYPE_TARGET_PREFIX,
                                events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE]))
        XCTAssertEqual(PathMute(path: "/usr/bin/true", typeName: "ES_MUTE_PATH_TYPE_LITERAL", eventNames: []),
                       PathMute(path: "/usr/bin/true", type: ES_MUTE_PATH_TYPE_LITERAL))
        for type in [ES_MUTE_PATH_TYPE_PREFIX, ES_MUTE_PATH_TYPE_LITERAL, ES_MUTE_PATH_TYPE_TARGET_PREFIX,
                     ES_MUTE_PATH_TYPE_TARGET_LITERAL] {
            let name = getMuteCaseString(muteType: type)
            XCTAssertEqual(PathMute(path: "/a", typeName: name, eventNames: [])?.type, type, name)
        }
        XCTAssertEqual(PathMute(path: "/a", typeName: "ES_MUTE_PATH_TYPE_PREFIX",
                                eventNames: ["ES_EVENT_TYPE_AUTH_OPEN"])?.events, [ES_EVENT_TYPE_AUTH_OPEN])
    }
    
    /// A name Mac Monitor doesn't know, or an empty path, is refused rather than muted as something else.
    func testBadXPCNamesAreRefused() {
        XCTAssertNil(PathMute(path: "", typeName: "ES_MUTE_PATH_TYPE_LITERAL", eventNames: []))
        XCTAssertNil(PathMute(path: "/a", typeName: "ES_MUTE_PATH_TYPE_BOGUS", eventNames: []))
        XCTAssertNil(PathMute(path: "/a", typeName: "", eventNames: []))
        XCTAssertNil(PathMute(path: "/a", typeName: "ES_MUTE_PATH_TYPE_LITERAL",
                              eventNames: ["ES_EVENT_TYPE_NOTIFY_OPEN", "ES_EVENT_TYPE_NOTIFY_BOGUS"]))
        XCTAssertNil(PathMute(path: "/a", typeName: "ES_MUTE_PATH_TYPE_LITERAL", eventNames: ["ES_EVENT_TYPE_LAST"]))
    }
    
    /// Dropping unknown event names keeps the known ones in order; a request that names only unknown events is still
    /// refused, rather than read as every event, and so are a bad path and type.
    func testUnknownEventNamesCanBeDropped() {
        let names = ["ES_EVENT_TYPE_NOTIFY_OPEN", "ES_EVENT_TYPE_LAST", "ES_EVENT_TYPE_NOTIFY_BOGUS",
                     "ES_EVENT_TYPE_NOTIFY_CLOSE"]
        XCTAssertEqual(PathMute(path: "/a", typeName: "ES_MUTE_PATH_TYPE_LITERAL", eventNames: names,
                                unknownEvents: .drop),
                       PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL,
                                events: [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE]))
        XCTAssertEqual(PathMute(path: "/a", typeName: "ES_MUTE_PATH_TYPE_LITERAL", eventNames: [],
                                unknownEvents: .drop),
                       PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL))
        XCTAssertNil(PathMute(path: "/a", typeName: "ES_MUTE_PATH_TYPE_LITERAL",
                              eventNames: ["ES_EVENT_TYPE_LAST", "ES_EVENT_TYPE_NOTIFY_BOGUS"], unknownEvents: .drop))
        XCTAssertNil(PathMute(path: "", typeName: "ES_MUTE_PATH_TYPE_LITERAL", eventNames: names, unknownEvents: .drop))
        XCTAssertNil(PathMute(path: "/a", typeName: "ES_MUTE_PATH_TYPE_BOGUS", eventNames: names, unknownEvents: .drop))
    }
    
    /// A global mute as Endpoint Security lists it, every event type up to `ES_EVENT_TYPE_LAST` with the ones Mac
    /// Monitor doesn't name listed as `ES_EVENT_TYPE_LAST`, unmutes every type Mac Monitor names.
    func testEndpointSecuritysListOfAGlobalMuteCanBeUnmuted() throws {
        let types = (0..<ES_EVENT_TYPE_LAST.rawValue).map { es_event_type_t(rawValue: $0) }
        let names = types.map { eventTypeToString(from: $0) }
        let unmute = try XCTUnwrap(PathMute(path: "/usr/libexec/logd", typeName: "ES_MUTE_PATH_TYPE_LITERAL",
                                            eventNames: names, unknownEvents: .drop))
        XCTAssertEqual(unmute.events, zip(types, names).filter { $1 != "ES_EVENT_TYPE_LAST" }.map(\.0))
        XCTAssertTrue(unmute.events.contains(ES_EVENT_TYPE_NOTIFY_EXEC))
    }
}
