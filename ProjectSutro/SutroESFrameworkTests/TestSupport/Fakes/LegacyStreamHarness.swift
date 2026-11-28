//
//  LegacyStreamHarness.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - An older Security Extension
/// A Security Extension older than `macmonitor`, in the test process: it relays each `macmonitor` connection to a
/// ``StreamHarness``, reading each stream request as that release reads it (``Release``).
final class LegacyStreamHarness: NSObject, NSXPCListenerDelegate {
    /// The releases it stands for.
    enum Release {
        /// 3.0.0 ignores a request's ``StreamOptions/fieldFilters``. The stream then applies no field filter, and its
        /// answer echoes none.
        case v3_0
        /// 3.2.0 doesn't know the network flow events, and refuses a stream that names one.
        case v3_2
    }

    private let harness: StreamHarness
    private let release: Release
    private let listener = NSXPCListener.anonymous()
    /// Every connection's relay, kept for as long as the harness.
    private let relays = Recorded<LegacyStreamRelay>()

    /// - Parameters:
    ///   - harness: The Security Extension the relays connect to.
    ///   - release: The release it stands for: 3.0.0 unless given.
    init(relayingTo harness: StreamHarness, as release: Release = .v3_0) {
        self.harness = harness
        self.release = release
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
        let relay = LegacyStreamRelay(downstream: connection, harness: harness, release: release)
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
/// One `macmonitor` connection's relay: stream requests go up to the harness as the release reads them, and batches
/// and saved mute set changes come back down unchanged.
final class LegacyStreamRelay: NSObject, StreamProtocol, StreamReaderProtocol {
    /// `macmonitor`'s connection, which keeps the relay as its exported object.
    private weak var downstream: NSXPCConnection?
    /// The release it reads requests as.
    private let release: LegacyStreamHarness.Release
    /// The connection to the harness's service, which streams to the relay.
    private var upstream: NSXPCConnection?

    /// - Parameters:
    ///   - downstream: `macmonitor`'s connection.
    ///   - harness: The Security Extension to relay to.
    ///   - release: The release it reads requests as.
    init(downstream: NSXPCConnection, harness: StreamHarness, release: LegacyStreamHarness.Release) {
        self.downstream = downstream
        self.release = release
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

    /// Relay a request as the release reads it: 3.0.0 without its field filters, and 3.2.0 refusing a stream that
    /// names a network flow event, in 3.2.0's words.
    ///
    /// - Parameters:
    ///   - request: A JSON encoded ``StreamRequest``.
    ///   - reply: The harness's answer, or the refusal.
    func perform(_ request: Data, reply: @escaping (Data) -> Void) {
        guard var decoded = try? StreamRequest.decode(request) else {
            service?.perform(request, reply: reply)
            return
        }
        switch release {
        case .v3_0:
            decoded.options?.fieldFilters = nil
        case .v3_2:
            if let flow = decoded.options?.events.first(where: { MacMonitorEvent(name: $0) != nil }) {
                let problem = "\(flow) isn't an event macmonitor can stream on this Mac."
                return reply(StreamReply(status: .invalid, problem: problem, sensorVersion: "3.2.0 (1)").encoded())
            }
        }
        service?.perform(decoded.encoded(), reply: reply)
    }

    /// Relay a mute request unchanged.
    ///
    /// - Parameters:
    ///   - request: A JSON encoded ``MuteRequest``.
    ///   - reply: The harness's answer.
    func mutes(_ request: Data, reply: @escaping (Data) -> Void) {
        service?.mutes(request, reply: reply)
    }

    /// Relay an indicator request unchanged.
    ///
    /// - Parameters:
    ///   - request: A JSON encoded ``IndicatorRequest``.
    ///   - reply: The harness's answer.
    func indicators(_ request: Data, reply: @escaping (Data) -> Void) {
        service?.indicators(request, reply: reply)
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
