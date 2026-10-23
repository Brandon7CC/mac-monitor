//
//  MuteListChangesTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Changes between mute lists
/// Pins the Endpoint Security calls that move a client from one mute list to another: their exact order for each kind
/// of change, and that any sequence of them lands on the target without unmuting what both lists mute.
final class MuteListChangesTests: XCTestCase {
    private let close = ES_EVENT_TYPE_NOTIFY_CLOSE, exec = ES_EVENT_TYPE_NOTIFY_EXEC, open = ES_EVENT_TYPE_NOTIFY_OPEN
    /// The events the property test draws from.
    private let universe: [es_event_type_t] = [ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_EXEC,
                                               ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_WRITE,
                                               ES_EVENT_TYPE_NOTIFY_MMAP]
    /// The keys the property test draws from.
    private let keys = [MuteList.Key(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL),
                        MuteList.Key(path: "/a", type: ES_MUTE_PATH_TYPE_PREFIX),
                        MuteList.Key(path: "/b", type: ES_MUTE_PATH_TYPE_TARGET_PREFIX)]
    
    /// A list with one entry for `/a`, matched literally.
    ///
    /// - Parameter events: Its events. None means every event.
    /// - Returns: The list.
    private func list(_ events: [es_event_type_t]) -> MuteList {
        MuteList([PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL, events: events)])
    }
    
    /// One call for `/a`, matched literally.
    ///
    /// - Parameters:
    ///   - event: Its one event, or `nil` for every event.
    ///   - muted: `true` to mute.
    /// - Returns: The call.
    private func call(_ event: es_event_type_t?, _ muted: Bool) -> MuteChange {
        MuteChange(PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL, events: event.map { [$0] } ?? []),
                   muted: muted)
    }
    
    /// A new entry is muted one event at a time, in name order, or with one call for every event.
    func testNewEntriesAreMuted() {
        XCTAssertEqual(MuteList().changes(to: list([open, close])), [call(close, true), call(open, true)])
        XCTAssertEqual(MuteList().changes(to: list([])), [call(nil, true)])
    }
    
    /// A gone entry is unmuted the way it was muted.
    func testGoneEntriesAreUnmuted() {
        XCTAssertEqual(list([open, close]).changes(to: MuteList()), [call(close, false), call(open, false)])
        XCTAssertEqual(list([]).changes(to: MuteList()), [call(nil, false)])
    }
    
    /// From some events to others, the new ones are muted before the old ones are unmuted, and shared ones untouched.
    func testSomeEventsToOthersMutesBeforeUnmuting() {
        XCTAssertEqual(list([open, close]).changes(to: list([open, exec])), [call(exec, true), call(close, false)])
    }
    
    /// From some events to every event takes one mute and no unmute, which would subtract the old events again.
    func testSomeEventsToEveryEventOnlyMutesEverything() {
        XCTAssertEqual(list([open, close]).changes(to: list([])), [call(nil, true)])
    }
    
    /// From every event to some, the key is cleared first and then muted for the events kept.
    func testEveryEventToSomeClearsFirst() {
        XCTAssertEqual(list([]).changes(to: list([open, close])),
                       [call(nil, false), call(close, true), call(open, true)])
    }
    
    /// Equal lists need no calls.
    func testEqualListsNeedNoCalls() {
        XCTAssertEqual(list([open]).changes(to: list([open])), [])
        XCTAssertEqual(MuteList.testDefault.changes(to: .testDefault), [])
    }
    
    /// Keys change in canonical order, by type name then path.
    func testKeysChangeInCanonicalOrder() {
        let target = MuteList([PathMute(path: "/b", type: ES_MUTE_PATH_TYPE_TARGET_PREFIX),
                               PathMute(path: "/z", type: ES_MUTE_PATH_TYPE_LITERAL),
                               PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_PREFIX)])
        XCTAssertEqual(MuteList().changes(to: target).map(\.mute.path), ["/z", "/a", "/b"])
    }
    
    /// The difference names the mutes only the new list has, those only the old one has, and those both have for
    /// different events, each in canonical order.
    func testTheDifferenceIsByPathAndType() {
        let old = MuteList([PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL, events: [exec]),
                            PathMute(path: "/b", type: ES_MUTE_PATH_TYPE_TARGET_PREFIX),
                            PathMute(path: "/c", type: ES_MUTE_PATH_TYPE_LITERAL, events: [open])])
        let new = MuteList([PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL, events: [exec, open]),
                            PathMute(path: "/c", type: ES_MUTE_PATH_TYPE_LITERAL, events: [open]),
                            PathMute(path: "/z", type: ES_MUTE_PATH_TYPE_PREFIX),
                            PathMute(path: "/y", type: ES_MUTE_PATH_TYPE_PREFIX)])
        let difference = old.difference(to: new)
        XCTAssertEqual(difference.added, [MuteList.Key(path: "/y", type: ES_MUTE_PATH_TYPE_PREFIX),
                                          MuteList.Key(path: "/z", type: ES_MUTE_PATH_TYPE_PREFIX)])
        XCTAssertEqual(difference.removed, [MuteList.Key(path: "/b", type: ES_MUTE_PATH_TYPE_TARGET_PREFIX)])
        XCTAssertEqual(difference.changed, [MuteList.Key(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL)])
        XCTAssertFalse(difference.isEmpty)
        XCTAssertTrue(new.difference(to: new).isEmpty)
    }
    
    /// Applying the changes to Endpoint Security's model of the old list gives the new list, for 2,000 seeded pairs.
    /// What both lists mute is never unmuted along the way, except where every event narrows to some.
    func testChangesReachTheTargetWithoutGaps() {
        var generator = SeededGenerator(seed: 2_026_10_05)
        let universe = Set(self.universe)
        for _ in 0..<2_000 {
            let old = randomList(&generator), new = randomList(&generator)
            var model = EndpointSecurityMuteModel(old, universe: universe)
            let target = EndpointSecurityMuteModel(new, universe: universe)
            let shared = model.tuples.intersection(target.tuples).filter { tuple in
                !(old.scopes[tuple.key] == .allEvents && new.scopes[tuple.key] != .allEvents)
            }
            for change in old.changes(to: new) {
                model.apply(change)
                XCTAssertTrue(shared.isSubset(of: model.tuples), "\(old) → \(new) unmuted a shared tuple")
            }
            XCTAssertEqual(model, target, "\(old) → \(new)")
        }
    }
    
    /// A random list over ``keys`` and ``universe``: each key missing, muted for every event, or for some events.
    ///
    /// - Parameter generator: The seeded generator.
    /// - Returns: The list.
    private func randomList(_ generator: inout SeededGenerator) -> MuteList {
        var list = MuteList()
        for key in keys {
            switch Int.random(in: 0..<10, using: &generator) {
            case 0..<3:
                continue
            case 3..<5:
                list.add(PathMute(path: key.path, type: key.type))
            default:
                let events = universe.filter { _ in Bool.random(using: &generator) }
                if !events.isEmpty { list.add(PathMute(path: key.path, type: key.type, events: events)) }
            }
        }
        return list
    }
}
