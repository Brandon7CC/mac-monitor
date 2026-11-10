//
//  CommandLineAccessSkewTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Settings against a 3.0 Security Extension
/// Pins what Settings' requests added in 3.1 do to Mac Monitor's own connection: an app updated before its Security
/// Extension, or one whose update hasn't been approved yet, talks to a 3.0.0 Security Extension, which closes the
/// connection that sends a call it doesn't know. That connection owns the event stream, and closing it stops
/// capture, so Settings' command line access and indicator requests must leave it be. Against this build's Security
/// Extension they work, and a change still comes from the connection that owns the event stream.
final class CommandLineAccessSkewTests: XCTestCase {
    /// Refreshing Settings > Command Line, and changing the level, gets no answer from a 3.0.0 Security Extension,
    /// and Mac Monitor still owns the event stream on the connection it handshook on.
    func testASettingsRefreshKeepsAThreeZeroStream() throws {
        let service = FakeSensorService(.v3_0)
        let manager = owner(of: service)
        XCTAssertNil(try XCTUnwrap(answer { manager.commandLineAccess(completion: $0) }))
        XCTAssertEqual(answer { manager.setCommandLineAccess(.streaming, completion: $0) }, .unavailable)
        assertStillOwns(manager, service)
    }

    /// Settings > Indicators' refresh gets no set from a 3.0.0 Security Extension, and leaves the stream be too.
    func testAnIndicatorRefreshKeepsAThreeZeroStream() throws {
        let service = FakeSensorService(.v3_0)
        let manager = owner(of: service)
        let reply = try XCTUnwrap(answer { manager.indicatorTransport(IndicatorRequest(.list).encoded(), $0) })
        XCTAssertNil(reply)
        assertStillOwns(manager, service)
    }

    /// This build's Security Extension answers, and takes a change from Mac Monitor while it owns the event stream:
    /// only the connection that owns it may make one, so a change can't go on a connection of its own.
    func testThisBuildsSecurityExtensionTakesTheOwnersChange() throws {
        let service = FakeSensorService(.current)
        let manager = owner(of: service)
        XCTAssertEqual(try XCTUnwrap(answer { manager.commandLineAccess(completion: $0) }), .rootOnly)
        XCTAssertEqual(answer { manager.setCommandLineAccess(.streaming, completion: $0) }, .done)
        XCTAssertEqual(try XCTUnwrap(answer { manager.commandLineAccess(completion: $0) }), .streaming)
        assertStillOwns(manager, service)
    }

    /// The app updated first: a 3.0.0 Security Extension answers neither request. Once the update to the Security
    /// Extension is approved, it replaces the old one and Mac Monitor handshakes again, and both requests are asked
    /// about anew, so the change goes through without relaunching Mac Monitor.
    func testAHandshakeWithANewerSecurityExtensionAsksAgain() throws {
        let manager = owner(of: FakeSensorService(.v3_0))
        XCTAssertEqual(answer { manager.setCommandLineAccess(.streaming, completion: $0) }, .unavailable)
        XCTAssertNil(try XCTUnwrap(answer { manager.indicatorTransport(IndicatorRequest(.list).encoded(), $0) }))
        let updated = FakeSensorService(.current)
        handshake(manager, with: updated)
        XCTAssertEqual(answer { manager.setCommandLineAccess(.streaming, completion: $0) }, .done)
        XCTAssertNotNil(try XCTUnwrap(answer { manager.indicatorTransport(IndicatorRequest(.list).encoded(), $0) }))
        assertStillOwns(manager, updated)
    }

    // MARK: Helpers
    /// A manager whose connections go to `service`, after a handshake that made it the event stream's owner.
    ///
    /// - Parameter service: The Security Extension.
    /// - Returns: The manager.
    private func owner(of service: FakeSensorService) -> EndpointSecurityManager {
        let manager = EndpointSecurityManager()
        handshake(manager, with: service)
        return manager
    }

    /// Point `manager`'s connections at `service` and handshake there, as Mac Monitor does when the Security
    /// Extension it talked to is replaced: that one's connection ends, and the next is made to the new one.
    ///
    /// - Parameters:
    ///   - manager: Mac Monitor's manager.
    ///   - service: The Security Extension running now.
    private func handshake(_ manager: EndpointSecurityManager, with service: FakeSensorService,
                           file: StaticString = #filePath, line: UInt = #line) {
        manager.sensor = SensorClient(agent: SilentAgent(), connect: {
            NSXPCConnection(listenerEndpoint: service.endpoint)
        }) { _ in }
        let ready = expectation(forNotification: IndicatorEngine.sensorReady, object: manager)
        manager.kickoffXPCCommunication()
        wait(for: [ready], timeout: 5)
        XCTAssertEqual(manager.connectionResult, .success, file: file, line: line)
    }

    /// The connection `manager` handshook on is still open, and still the one that owns the event stream.
    ///
    /// - Parameters:
    ///   - manager: Mac Monitor's manager.
    ///   - service: The Security Extension.
    private func assertStillOwns(_ manager: EndpointSecurityManager, _ service: FakeSensorService,
                                 file: StaticString = #filePath, line: UInt = #line) {
        let owns = answer { done in
            manager.sensor.call { $0.setRecording(false, reply: $1) } completion: { done($0) }
        }
        XCTAssertEqual(owns, .some(true), "Mac Monitor no longer owns the event stream", file: file, line: line)
        XCTAssertFalse(service.ownerClosed, "The owner's connection closed", file: file, line: line)
        XCTAssertEqual(service.starts, 1, file: file, line: line)
    }

    /// Wait for one reply.
    ///
    /// - Parameter ask: Sends the request, passing the reply on.
    /// - Returns: The reply, or `nil` if none came in time.
    private func answer<Reply>(_ ask: (@escaping (Reply) -> Void) -> Void) -> Reply? {
        let replied = expectation(description: "reply")
        var reply: Reply?
        ask {
            reply = $0
            replied.fulfill()
        }
        wait(for: [replied], timeout: 5)
        return reply
    }
}
