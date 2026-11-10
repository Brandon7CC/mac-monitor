//
//  SubscriptionsLoadTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import Combine
import XCTest
@testable import SutroESFramework


// MARK: - Loading the event subscriptions
/// Pins when Mac Monitor knows the Security Extension's event subscriptions: not before it's asked, and from the
/// handshake on, without Settings > Subscriptions asking first. Until then
/// ``EndpointSecurityManager/monitoredEventStrings`` is empty because nothing is known, which the pane must not show
/// as nothing subscribed.
final class SubscriptionsLoadTests: XCTestCase {
    /// A new manager knows nothing yet, and says so.
    func testANewManagerHasNoAnswerYet() {
        let manager = EndpointSecurityManager()
        XCTAssertFalse(manager.hasEventSubscriptions)
        XCTAssertTrue(manager.monitoredEventStrings.isEmpty)
    }

    /// The handshake asks for the subscriptions itself. A Security Extension subscribed to nothing answers with none,
    /// which is then known rather than unknown.
    func testTheHandshakeLoadsTheSubscriptions() {
        let service = FakeSensorService(.current)
        let manager = EndpointSecurityManager()
        manager.sensor = SensorClient(agent: SilentAgent(), connect: {
            NSXPCConnection(listenerEndpoint: service.endpoint)
        }) { _ in }
        let loaded = expectation(description: "The subscriptions were loaded")
        let watching = manager.$hasEventSubscriptions.filter { $0 }.first().sink { _ in loaded.fulfill() }
        manager.kickoffXPCCommunication()
        wait(for: [loaded], timeout: 5)
        watching.cancel()
        XCTAssertEqual(manager.connectionResult, .success)
        XCTAssertTrue(manager.hasEventSubscriptions)
        XCTAssertTrue(manager.monitoredEventStrings.isEmpty)
    }
}
