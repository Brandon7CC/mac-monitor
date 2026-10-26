//
//  IdentityHashableTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/26/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Payload identity
/// Pins that a payload is one event by its id alone (``IdentityHashable``): the protocol's `==` and `hash(into:)` win
/// over the ones Swift would synthesize from every field.
final class IdentityHashableTests: XCTestCase {
    /// Assert that two payloads whose other fields differ are not equal, then are equal and hash equally once they
    /// share an id.
    ///
    /// - Parameters:
    ///   - first: A payload.
    ///   - other: A payload with another id and other fields.
    ///   - id: The payload's id, which `other` takes from `first`.
    ///   - line: The caller's line.
    private func assertOneEvent<Payload: IdentityHashable>(_ first: Payload, _ other: Payload,
                                                           id: WritableKeyPath<Payload, Payload.ID>,
                                                           line: UInt = #line) {
        XCTAssertNotEqual(first, other, line: line)
        var second = other
        second[keyPath: id] = first.id
        XCTAssertEqual(first, second, line: line)
        XCTAssertEqual(first.hashValue, second.hashValue, line: line)
    }

    /// A `remote_thread_create`, whose `==` compared its target and thread state before, and an `exit`, whose hash
    /// was its status, are one event by id whatever their fields hold.
    func testSameIdIsOneEvent() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE)
        let process = { (path: String, pid: Int32) in
            SutroESFramework.Process(from: fixture.process(path: path, pid: pid).pointee, version: 10)
        }
        let running = RemoteThreadCreateEvent(target: process("/bin/sleep", 4243),
                                              threadState: fixture.threadState(bytes: [0, 1, 2, 0xFF]))
        let created = RemoteThreadCreateEvent(target: process("/usr/bin/true", 123), threadState: nil)
        assertOneEvent(running, created, id: \.id)

        let exit = { (stat: Int32) -> ProcessExitEvent in
            let message = self.rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
            message.message.pointee.event.exit.stat = stat
            return ProcessExitEvent(from: message.raw)
        }
        assertOneEvent(exit(0), exit(256), id: \.id)
    }
}
