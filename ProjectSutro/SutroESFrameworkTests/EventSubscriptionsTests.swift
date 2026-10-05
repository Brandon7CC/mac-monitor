//
//  EventSubscriptionsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Event subscriptions
/// Pins which events Mac Monitor offers and subscribes to, and that each has its own icon.
final class EventSubscriptionsTests: XCTestCase {
    /// The icon ``eventStringToImage(from:)`` gives an event it doesn't know.
    private static let unknownEventIcon = "questionmark.app.dashed"
    
    /// Every Open Directory event Mac Monitor records is offered and subscribed to by default from macOS 14, as
    /// `od_group_remove` wasn't.
    ///
    /// - Throws: `XCTSkip` before macOS 14, which has no Open Directory events.
    func testOpenDirectoryEvents() throws {
        try XCTSkipUnless(ProcessInfo().isOperatingSystemAtLeast(sonoma), "Open Directory events need macOS 14")
        for event in RawMessageFixture.openDirectoryEvents.map(\.type) {
            XCTAssertTrue(supportedEvents.contains(event), eventTypeToString(from: event))
            XCTAssertTrue(defaultEventSubscriptions.contains(event), eventTypeToString(from: event))
        }
    }
    
    /// Every event offered has its own icon.
    func testEveryEventHasAnIcon() {
        for event in supportedEvents {
            let name = eventTypeToString(from: event)
            XCTAssertNotEqual(eventStringToImage(from: name), Self.unknownEventIcon, name)
        }
    }
    
    /// Every event offered is a NOTIFY event Mac Monitor names, offered once: a capture session subscribes only to
    /// these.
    func testSupportedEventsAreNotifyOnly() {
        for event in supportedEvents {
            let name = eventTypeToString(from: event)
            XCTAssertTrue(name.hasPrefix("ES_EVENT_TYPE_NOTIFY_"), name)
            XCTAssertNotEqual(event, ES_EVENT_TYPE_LAST, name)
        }
        XCTAssertEqual(Set(supportedEvents.map(\.rawValue)).count, supportedEvents.count)
        XCTAssertEqual(Set(defaultEventSubscriptions.map(\.rawValue)).count, defaultEventSubscriptions.count)
    }
}
