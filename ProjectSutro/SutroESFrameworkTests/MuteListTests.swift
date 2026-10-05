//
//  MuteListTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Mute lists
/// Pins mute lists as values: one scope per path and type, merged as Endpoint Security merges mutes, and listed in a
/// canonical order.
final class MuteListTests: XCTestCase {
    private let open = ES_EVENT_TYPE_NOTIFY_OPEN, close = ES_EVENT_TYPE_NOTIFY_CLOSE, exec = ES_EVENT_TYPE_NOTIFY_EXEC
    
    /// A mute, of `/a` unless a test names another path.
    ///
    /// - Parameters:
    ///   - events: Its events. None means every event.
    ///   - type: Its type.
    ///   - path: Its path.
    /// - Returns: The mute.
    private func mute(_ events: [es_event_type_t] = [], type: es_mute_path_type_t = ES_MUTE_PATH_TYPE_LITERAL,
                      path: String = "/a") -> PathMute {
        PathMute(path: path, type: type, events: events)
    }
    
    /// Adding merges events by path and type; the same path with another type is another entry.
    func testAddingMergesEventsByPathAndType() {
        var list = MuteList()
        XCTAssertTrue(list.add(mute([open])))
        XCTAssertTrue(list.add(mute([close, open])))
        XCTAssertFalse(list.add(mute([close])))
        XCTAssertTrue(list.add(mute([open], type: ES_MUTE_PATH_TYPE_PREFIX)))
        XCTAssertEqual(list.count, 2)
        XCTAssertEqual(list.scopes[MuteList.Key(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL)], .events([open, close]))
        XCTAssertEqual(list.scopes[MuteList.Key(path: "/a", type: ES_MUTE_PATH_TYPE_PREFIX)], .events([open]))
    }
    
    /// A mute for every event absorbs scoped ones, whether it comes before or after them.
    func testAllEventsAbsorbsScopedMutes() {
        let key = MuteList.Key(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL)
        var before = MuteList()
        XCTAssertTrue(before.add(mute()))
        XCTAssertFalse(before.add(mute([open])))
        var after = MuteList()
        after.add(mute([open]))
        XCTAssertTrue(after.add(mute()))
        XCTAssertFalse(after.add(mute()))
        XCTAssertEqual(before, after)
        XCTAssertEqual(after.scopes[key], .allEvents)
    }
    
    /// Removing with no events removes the path, whatever its scope.
    ///
    /// - Throws: An unexpected ``MuteListError``.
    func testRemovingWithNoEventsRemovesThePath() throws {
        var list = MuteList([mute([open, close]), mute(path: "/b")])
        XCTAssertTrue(try list.remove(mute()))
        XCTAssertTrue(try list.remove(mute(path: "/b")))
        XCTAssertTrue(list.isEmpty)
    }
    
    /// Removing events subtracts them, and removing the last one removes the path.
    ///
    /// - Throws: An unexpected ``MuteListError``.
    func testRemovingEventsSubtractsThem() throws {
        var list = MuteList([mute([open, close, exec])])
        XCTAssertTrue(try list.remove(mute([open, exec])))
        XCTAssertEqual(list.scopes.values.first, .events([close]))
        XCTAssertTrue(try list.remove(mute([close])))
        XCTAssertTrue(list.isEmpty)
    }
    
    /// Removing some events of a path muted for every event is refused, and the list is left as it was.
    func testNarrowingAnAllEventsMuteIsRefused() {
        var list = MuteList([mute()])
        let before = list
        XCTAssertThrowsError(try list.remove(mute([open]))) { error in
            XCTAssertEqual(error as? MuteListError, .narrowsAllEvents(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL))
            XCTAssertTrue("\(error)".contains("Remove it, then add it back"))
        }
        XCTAssertEqual(list, before)
    }
    
    /// Removing what isn't muted changes nothing.
    ///
    /// - Throws: An unexpected ``MuteListError``.
    func testRemovingWhatIsNotMutedChangesNothing() throws {
        var list = MuteList([mute([open])])
        let before = list
        XCTAssertFalse(try list.remove(mute([close])))
        XCTAssertFalse(try list.remove(mute(path: "/b")))
        XCTAssertFalse(try list.remove(mute(type: ES_MUTE_PATH_TYPE_PREFIX)))
        XCTAssertEqual(list, before)
    }
    
    /// Mutes come out in canonical order, by type name then path, each with its events in name order.
    func testMutesComeOutInCanonicalOrder() {
        let list = MuteList([
            mute([open, close, exec], type: ES_MUTE_PATH_TYPE_TARGET_PREFIX, path: "/z"),
            mute(type: ES_MUTE_PATH_TYPE_LITERAL, path: "/b"),
            mute([open], type: ES_MUTE_PATH_TYPE_PREFIX, path: "/a"),
            mute(type: ES_MUTE_PATH_TYPE_LITERAL, path: "/a")
        ])
        XCTAssertEqual(list.mutes, [
            mute(type: ES_MUTE_PATH_TYPE_LITERAL, path: "/a"),
            mute(type: ES_MUTE_PATH_TYPE_LITERAL, path: "/b"),
            mute([open], type: ES_MUTE_PATH_TYPE_PREFIX, path: "/a"),
            mute([close, exec, open], type: ES_MUTE_PATH_TYPE_TARGET_PREFIX, path: "/z")
        ])
        XCTAssertEqual(list.keys.map(\.path), ["/a", "/b", "/a", "/z"])
    }
    
    /// Adding another list's mutes merges them.
    func testAddingAListMergesIt() {
        var list = MuteList([mute([open])])
        XCTAssertTrue(list.add(contentsOf: MuteList([mute([close]), mute(path: "/b")])))
        XCTAssertFalse(list.add(contentsOf: MuteList([mute([open])])))
        XCTAssertEqual(list, MuteList([mute([open, close]), mute(path: "/b")]))
    }
    
    /// The shipped default holds every mute of Mac Monitor's default set: one entry per distinct path and type, each
    /// covering its mutes' events or every event. The repeated `/Library/SystemExtensions/` OPEN rule is listed once.
    func testShippedDefaultHoldsTheDefaultSet() {
        let shipped = MuteList.shippedDefault(for: .tester)
        let mutes = MuteSet.default(home: ConsoleUser.tester.home).pathMutes
        let keys = Set(mutes.map { MuteList.Key(path: $0.path, type: $0.type) })
        XCTAssertEqual(shipped.count, keys.count)
        for mute in mutes {
            switch shipped.scopes[MuteList.Key(path: mute.path, type: mute.type)] {
            case .allEvents?:
                continue
            case .events(let events)?:
                XCTAssertFalse(mute.events.isEmpty, mute.path)
                XCTAssertTrue(events.isSuperset(of: mute.events), mute.path)
            case nil:
                XCTFail("\(mute.path) is missing")
            }
        }
        let systemExtensions = shipped.mutes.filter { $0.path == "/Library/SystemExtensions/" }
        XCTAssertEqual(systemExtensions.count, 1)
        XCTAssertEqual(systemExtensions.first?.events.filter { $0 == ES_EVENT_TYPE_NOTIFY_OPEN }.count, 1)
        XCTAssertLessThan(shipped.count, mutes.count)
    }
}
