//
//  MessageBundleAgeTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Bundle ages
/// Pins ``Message/deriveBundleAges()``: a launch item's bundle and app bundle get their ages at the event from their
/// birth times and the message's time, unless they have one. Unknown birth times give none, and a clock that stepped
/// back gives a negative age, which is kept and never shown.
final class MessageBundleAgeTests: XCTestCase {
    /// The message's time.
    private static let time = Date(timeIntervalSince1970: 1_791_072_114.394)

    /// A full synthetic launch item event, recorded at ``time``, whose bundles were born at `birth`, without ages.
    ///
    /// - Parameters:
    ///   - type: Add or remove.
    ///   - birth: Both bundles' birth time, or `nil` for none.
    /// - Returns: The event.
    /// - Throws: The error making the corpus, or an `XCTest` failure if it has no such record.
    private func message(_ type: es_event_type_t, birth: timespec?) throws -> Message {
        let name = type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD ? "btm_launch_item_add" : "btm_launch_item_remove"
        var message = try XCTUnwrap(try SyntheticCorpus.records().first { $0.label == "\(name) (full)" }).message
        message.message_darwin_time = Self.time
        let birthTime = birth.map(TimeSpec.init(from:))
        func reset(_ item: inout LaunchItem) {
            item.bundle?.birth_time = birthTime
            item.bundle?.age_ms = nil
            item.app_bundle?.birth_time = birthTime
            item.app_bundle?.age_ms = nil
        }
        switch message.event {
        case .btm_launch_item_add(var add):
            reset(&add.item)
            message.event = .btm_launch_item_add(add)
        case .btm_launch_item_remove(var remove):
            reset(&remove.item)
            message.event = .btm_launch_item_remove(remove)
        default:
            XCTFail("Not a launch item event")
        }
        return message
    }

    /// A launch item event's item.
    ///
    /// - Parameter message: The event.
    /// - Returns: The item, or `nil` for another event.
    private func item(of message: Message) -> LaunchItem? {
        switch message.event {
        case .btm_launch_item_add(let add): return add.item
        case .btm_launch_item_remove(let remove): return remove.item
        default: return nil
        }
    }

    /// Both bundles of an add and a remove are dated against the message: 1.5 s, to the millisecond.
    func testKnownBirth() throws {
        for type in [ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD, ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE] {
            var message = try message(type, birth: timespec(tv_sec: 1_791_072_112, tv_nsec: 894_000_000))
            message.deriveBundleAges()
            let item = try XCTUnwrap(item(of: message))
            XCTAssertEqual(item.bundle?.age_ms, 1_500)
            XCTAssertEqual(item.app_bundle?.age_ms, 1_500)
            XCTAssertEqual(item.bundle?.ageText, "1.50s")
        }
    }

    /// No birth time, or one of 0, gives no age.
    func testUnknownBirth() throws {
        for birth in [nil, timespec(tv_sec: 0, tv_nsec: 0)] {
            var message = try message(ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD, birth: birth)
            message.deriveBundleAges()
            XCTAssertNil(item(of: message)?.bundle?.age_ms)
            XCTAssertNil(item(of: message)?.app_bundle?.age_ms)
        }
    }

    /// A bundle born after the event (the clock stepped back) keeps its negative age, which isn't shown.
    func testNegativeAgeIsKeptAndHidden() throws {
        var message = try message(ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
                                  birth: timespec(tv_sec: 1_791_072_124, tv_nsec: 394_000_000))
        message.deriveBundleAges()
        let bundle = try XCTUnwrap(item(of: message)?.bundle)
        XCTAssertEqual(bundle.age_ms, -10_000)
        XCTAssertNil(bundle.age)
        XCTAssertNil(bundle.ageText)
    }

    /// A bundle's own age is never overwritten.
    func testAgeIsNeverOverwritten() throws {
        var message = try message(ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
                                  birth: timespec(tv_sec: 1_791_072_112, tv_nsec: 894_000_000))
        guard case .btm_launch_item_add(var add) = message.event else { return XCTFail("Not an add") }
        add.item.bundle?.age_ms = 42
        message.event = .btm_launch_item_add(add)
        message.deriveBundleAges()
        XCTAssertEqual(item(of: message)?.bundle?.age_ms, 42)
        XCTAssertEqual(item(of: message)?.app_bundle?.age_ms, 1_500)
    }

    /// Other events are left as they are.
    func testOtherEventsAreUntouched() throws {
        var message = try XCTUnwrap(try SyntheticCorpus.records().first { $0.label == "exit (full)" }).message
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let before = try encoder.encode(message)
        message.deriveBundleAges()
        XCTAssertEqual(try encoder.encode(message), before)
    }
}
