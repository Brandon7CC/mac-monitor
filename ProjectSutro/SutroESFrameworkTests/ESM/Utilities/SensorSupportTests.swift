//
//  SensorSupportTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Does the Security Extension answer a request added after 3.0?
/// Pins how Mac Monitor learns whether the Security Extension running now answers a request added after 3.0, such as
/// `indicators` or `setCommandLineAccess`: it asks once, on a connection of its own, and again only after a
/// handshake or a request with no reply. A Security Extension older than 3.1 closes the connection that asks, which
/// must never be the one that owns the event stream.
final class SensorSupportTests: XCTestCase {
    /// A probe whose answers the test gives, counting how often it's asked.
    private final class ScriptedProbe {
        var asked = 0
        var pending: [(Bool) -> Void] = []

        /// - Parameter answered: Called when the test answers.
        func ask(_ answered: @escaping (Bool) -> Void) {
            asked += 1
            pending.append(answered)
        }

        /// - Parameter answer: The answer to every pending probe.
        func answer(_ answer: Bool) {
            let waiting = pending
            pending = []
            waiting.forEach { $0(answer) }
        }
    }

    /// Requests that arrive while the probe is out share it, and once it's answered, the answer is known without
    /// asking again.
    func testOneProbeAnswersEveryRequest() {
        let probe = ScriptedProbe()
        let support = SensorSupport(probe: probe.ask)
        let answers = Recorded<Bool>()
        support.whenKnown { answers.append($0) }
        support.whenKnown { answers.append($0) }
        XCTAssertEqual(probe.asked, 1)
        XCTAssertNil(support.answers)
        probe.answer(true)
        support.whenKnown { answers.append($0) }
        XCTAssertEqual(answers.all, [true, true, true])
        XCTAssertEqual(probe.asked, 1)
        XCTAssertEqual(support.answers, true)
    }

    /// After a handshake, or a request with no reply, the Security Extension is asked again: it may be another
    /// version now.
    func testForgettingAsksAgain() {
        let probe = ScriptedProbe()
        let support = SensorSupport(probe: probe.ask)
        support.whenKnown { _ in }
        probe.answer(false)
        support.forget()
        let answers = Recorded<Bool>()
        support.whenKnown { answers.append($0) }
        XCTAssertEqual(probe.asked, 2)
        probe.answer(true)
        XCTAssertEqual(answers.all, [true])
        XCTAssertEqual(support.answers, true)
    }

    /// An answer asked for before a handshake goes to the requests waiting on it, and isn't kept: the next request
    /// asks the Security Extension running now.
    func testAnAnswerFromBeforeAHandshakeIsNotKept() {
        let probe = ScriptedProbe()
        let support = SensorSupport(probe: probe.ask)
        let answers = Recorded<Bool>()
        support.whenKnown { answers.append($0) }
        support.forget()
        probe.answer(false)
        XCTAssertEqual(answers.all, [false])
        XCTAssertNil(support.answers)
        support.whenKnown { answers.append($0) }
        XCTAssertEqual(probe.asked, 2)
    }

    /// A Security Extension that doesn't answer is sent nothing, and the request has no reply, on the main queue.
    func testNothingIsSentToOneThatDoesNotAnswer() {
        let probe = ScriptedProbe()
        let support = SensorSupport(probe: probe.ask)
        var sent = 0
        let replied = expectation(description: "reply")
        support.send({ (answer: @escaping (Int?) -> Void) in
            sent += 1
            answer(1)
        }, completion: { reply in
            XCTAssertNil(reply)
            XCTAssertTrue(Thread.isMainThread)
            replied.fulfill()
        })
        probe.answer(false)
        wait(for: [replied], timeout: 5)
        XCTAssertEqual(sent, 0)
    }

    /// One that answers is sent the request, and its reply comes back. A request with no reply means asking again
    /// before the next one. One with a reply doesn't.
    func testARequestWithNoReplyAsksAgain() {
        let probe = ScriptedProbe()
        let support = SensorSupport(probe: probe.ask)
        let replies = Recorded<Int?>()
        support.send({ $0(7) }, completion: { replies.append($0) })
        probe.answer(true)
        support.send({ $0(8) }, completion: { replies.append($0) })
        XCTAssertEqual(probe.asked, 1)
        support.send({ (answer: @escaping (Int?) -> Void) in answer(nil) }, completion: { replies.append($0) })
        XCTAssertNil(support.answers)
        support.send({ $0(9) }, completion: { replies.append($0) })
        XCTAssertEqual(probe.asked, 2)
        probe.answer(true)
        XCTAssertEqual(replies.all, [7, 8, nil, 9])
    }
}


// MARK: - Probing on a connection of its own
/// Pins ``SensorClient``'s probe against listeners in the test process: a Security Extension older than 3.1 closes
/// the connection that sends `indicators`, and only that one. One that knows the call answers it.
final class SensorClientProbeTests: XCTestCase {
    /// Exports the one call a Security Extension from 3.1 on answers here.
    @objc private protocol IndicatorAnswering {
        func indicators(_ request: Data, reply: @escaping (Data) -> Void)
    }

    /// A Security Extension from 3.1 on, in the test process: it answers every indicator request with the list.
    private final class ServiceWithIndicators: NSObject, NSXPCListenerDelegate, IndicatorAnswering {
        /// The listener a test connects to by its endpoint.
        let listener = NSXPCListener.anonymous()

        /// Starts listening.
        override init() {
            super.init()
            listener.delegate = self
            listener.activate()
        }

        /// Accepts every connection, exporting ``IndicatorAnswering``.
        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            connection.exportedInterface = NSXPCInterface(with: IndicatorAnswering.self)
            connection.exportedObject = self
            connection.activate()
            return true
        }

        /// Replies to any request with the shipped indicators and read access.
        func indicators(_ request: Data, reply: @escaping (Data) -> Void) {
            reply(IndicatorReply(status: .ok, indicators: Indicator.defaults, access: .read).encoded())
        }
    }

    /// An older Security Extension closes the probe's connection, so the probe gets no reply, on the main queue.
    /// Another connection to it, as Mac Monitor's own is, still works.
    func testAnOlderSecurityExtensionClosesOnlyTheProbe() throws {
        let service = ServiceBeforeIndicators()
        let probed = probe(NSXPCConnection(listenerEndpoint: service.endpoint))
        XCTAssertEqual(probed.reply, .some(nil))
        XCTAssertEqual(probed.onMain, true)

        let own = NSXPCConnection(listenerEndpoint: service.endpoint)
        own.remoteObjectInterface = NSXPCInterface(with: StreamProtocolBeforeIndicators.self)
        own.activate()
        defer { own.invalidate() }
        let answered = expectation(description: "mutes")
        let proxy = own.remoteObjectProxyWithErrorHandler { error in XCTFail("\(error)") }
        try XCTUnwrap(proxy as? StreamProtocolBeforeIndicators).mutes(Data()) { _ in answered.fulfill() }
        wait(for: [answered], timeout: 5)
    }

    /// A Security Extension that knows the call answers the probe with its set.
    func testASecurityExtensionThatKnowsTheCallAnswers() throws {
        let service = ServiceWithIndicators()
        let probed = probe(NSXPCConnection(listenerEndpoint: service.listener.endpoint))
        let data = try XCTUnwrap(probed.reply.flatMap { $0 })
        XCTAssertEqual(IndicatorReply.decode(data)?.indicators, Indicator.defaults)
    }

    /// Probe `indicators` with a `list` on a connection, and wait for the answer.
    ///
    /// - Parameter connection: A connection not activated yet.
    /// - Returns: The reply (`.some(nil)` for none), and whether it came on the main queue.
    private func probe(_ connection: NSXPCConnection) -> (reply: Data??, onMain: Bool?) {
        let client = SensorClient(agent: SilentAgent()) { _ in }
        let done = expectation(description: "probe")
        var result: (reply: Data??, onMain: Bool?) = (nil, nil)
        client.send(caller: "test", { $0.indicators(IndicatorRequest(.list).encoded(), reply: $1) },
                    once: connection) { reply in
            result = (.some(reply), Thread.isMainThread)
            done.fulfill()
        }
        wait(for: [done], timeout: 5)
        return result
    }
}
