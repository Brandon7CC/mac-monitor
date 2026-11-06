//
//  LegacyStreamHarness.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - A 3.0.0 Security Extension
/// A Security Extension older than 3.0.1, in the test process: it relays each `macmonitor` connection to a
/// ``StreamHarness`` without the request's ``StreamOptions/fieldFilters``, as a 3.0.0 Security Extension ignores that
/// key. The stream then applies no field filter, and its answer echoes none.
final class LegacyStreamHarness: NSObject, NSXPCListenerDelegate {
    private let harness: StreamHarness
    private let listener = NSXPCListener.anonymous()
    /// Every connection's relay, kept for as long as the harness.
    private let relays = Recorded<LegacyStreamRelay>()

    /// - Parameter harness: The Security Extension the relays connect to.
    init(relayingTo harness: StreamHarness) {
        self.harness = harness
        super.init()
        listener.delegate = self
        listener.activate()
    }

    /// Where `macmonitor` connects.
    var endpoint: NSXPCListenerEndpoint {
        listener.endpoint
    }

    /// Relay each new connection to the harness, exporting what the Security Extension exports.
    ///
    /// - Parameters:
    ///   - listener: The anonymous listener.
    ///   - connection: The new connection, from `macmonitor`.
    /// - Returns: Always `true`.
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let relay = LegacyStreamRelay(downstream: connection, harness: harness)
        relays.append(relay)
        connection.exportedInterface = SensorXPC.streamInterface
        connection.exportedObject = relay
        connection.remoteObjectInterface = SensorXPC.streamReaderInterface
        connection.invalidationHandler = { relay.close() }
        connection.activate()
        return true
    }
}


// MARK: - Relay
/// One `macmonitor` connection's relay: requests go up to the harness without their field filters, and batches and
/// saved mute set changes come back down unchanged.
final class LegacyStreamRelay: NSObject, StreamProtocol, StreamReaderProtocol {
    /// `macmonitor`'s connection, which keeps the relay as its exported object.
    private weak var downstream: NSXPCConnection?
    /// The connection to the harness's service, which streams to the relay.
    private var upstream: NSXPCConnection?

    /// - Parameters:
    ///   - downstream: `macmonitor`'s connection.
    ///   - harness: The Security Extension to relay to.
    init(downstream: NSXPCConnection, harness: StreamHarness) {
        self.downstream = downstream
        super.init()
        upstream = harness.connect(reader: self)
    }

    /// Close the connection to the harness: its stream closes.
    func close() {
        upstream?.invalidate()
    }

    /// The harness's service.
    private var service: StreamProtocol? {
        upstream?.remoteObjectProxyWithErrorHandler { _ in } as? StreamProtocol
    }

    /// The `macmonitor` reader, or `nil` once it's gone.
    ///
    /// - Parameter failed: Called if the message to the reader fails.
    /// - Returns: The reader's proxy.
    private func reader(failed: @escaping () -> Void) -> StreamReaderProtocol? {
        downstream?.remoteObjectProxyWithErrorHandler { _ in failed() } as? StreamReaderProtocol
    }

    /// Relay a request without its field filters, as a 3.0.0 Security Extension reads it.
    ///
    /// - Parameters:
    ///   - request: A JSON encoded ``StreamRequest``.
    ///   - reply: The harness's answer.
    func perform(_ request: Data, reply: @escaping (Data) -> Void) {
        var forwarded = request
        if var decoded = try? StreamRequest.decode(request) {
            decoded.options?.fieldFilters = nil
            forwarded = decoded.encoded()
        }
        service?.perform(forwarded, reply: reply)
    }

    /// Relay a mute request unchanged.
    ///
    /// - Parameters:
    ///   - request: A JSON encoded ``MuteRequest``.
    ///   - reply: The harness's answer.
    func mutes(_ request: Data, reply: @escaping (Data) -> Void) {
        service?.mutes(request, reply: reply)
    }

    /// Relay a batch to `macmonitor`, and its reply back. A batch for a reader that's gone is replied to at once.
    ///
    /// - Parameters:
    ///   - events: The batch.
    ///   - reply: Lets the harness send the next batch.
    func receive(events: [Data], reply: @escaping () -> Void) {
        let finish = StreamClient.once { (_: Void) in reply() }
        guard let reader = reader(failed: { finish(()) }) else { return finish(()) }
        reader.receive(events: events) { finish(()) }
    }

    /// Relay a saved mute set change to `macmonitor`.
    ///
    /// - Parameter change: A JSON encoded ``MuteSetChange``.
    func savedMutesChanged(_ change: Data) {
        reader(failed: {})?.savedMutesChanged(change)
    }
}
