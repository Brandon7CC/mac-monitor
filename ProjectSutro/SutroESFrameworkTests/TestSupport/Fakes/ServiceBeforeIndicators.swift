//
//  ServiceBeforeIndicators.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - A Security Extension before indicators
/// The interface a Security Extension older than 3.1 exports to Mac Monitor: ``SensorProtocol`` as v3.0.0 declared
/// it, with no `indicators`, `commandLineAccess` or `setCommandLineAccess` call. ``XPCProtocolSnapshotTests`` holds
/// it to the selectors v3.0.0 shipped.
@objc protocol SensorProtocolBeforeIndicators {
    /// Claim the event stream and start capture.
    func start(recording: Bool, reply: @escaping (NewClientResult) -> Void)
    /// Start or stop serializing events.
    func setRecording(_ enabled: Bool, reply: @escaping (Bool) -> Void)
    /// The event subscriptions.
    func eventSubscriptions(reply: @escaping ([String]) -> Void)
    /// Subscribe to, or unsubscribe from, an event.
    func setSubscription(_ event: String, enabled: Bool, reply: @escaping (Bool) -> Void)
    /// Read or change the saved mute set.
    func mutes(_ request: Data, reply: @escaping (Data) -> Void)
    /// The paths Apple mutes by default.
    func appleMuteSet(reply: @escaping ([String]) -> Void)
    /// Check for a newer release.
    func checkForUpdate(reply: @escaping (Data?) -> Void)
    /// Install the latest release.
    func installUpdate(reply: @escaping (String?) -> Void)
    /// Install or remove the command line tool.
    func changeCommandLineTool(action: String, tool: String, expected: String, authorization: Data,
                               reply: @escaping (Int) -> Void)
}

/// The stream interface a Security Extension older than 3.1 exports: no `indicators` call.
@objc protocol StreamProtocolBeforeIndicators {
    /// Answer one stream request.
    ///
    /// - Parameters:
    ///   - request: A JSON encoded ``StreamRequest``.
    ///   - reply: A JSON encoded ``StreamReply``.
    func perform(_ request: Data, reply: @escaping (Data) -> Void)

    /// Read or change the saved mute set.
    ///
    /// - Parameters:
    ///   - request: A JSON encoded ``MuteRequest``.
    ///   - reply: A JSON encoded ``MuteReply``.
    func mutes(_ request: Data, reply: @escaping (Data) -> Void)
}

/// A Security Extension older than 3.1, in the test process: it exports the stream interface without `indicators`,
/// and counts the stream requests it gets.
final class ServiceBeforeIndicators: NSObject, NSXPCListenerDelegate, StreamProtocolBeforeIndicators {
    private let listener = NSXPCListener.anonymous()
    private let requests = Recorded<Data>()

    /// Start listening.
    override init() {
        super.init()
        listener.delegate = self
        listener.activate()
    }

    /// Where `macmonitor` connects.
    var endpoint: NSXPCListenerEndpoint {
        listener.endpoint
    }

    /// How many stream requests came.
    var streamRequests: Int {
        requests.all.count
    }

    /// Accept every connection, exporting the older interface.
    ///
    /// - Parameters:
    ///   - listener: The anonymous listener.
    ///   - connection: The new connection.
    /// - Returns: Always `true`.
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: StreamProtocolBeforeIndicators.self)
        connection.exportedObject = self
        connection.activate()
        return true
    }

    /// Count the request, and refuse it as unsupported.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - reply: Its answer.
    func perform(_ request: Data, reply: @escaping (Data) -> Void) {
        requests.append(request)
        reply(Data(#"{"version":1,"status":"unsupported","sensorVersion":"3.0.0 (1)"}"#.utf8))
    }

    /// Answer nothing useful: no test asks.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - reply: Its answer.
    func mutes(_ request: Data, reply: @escaping (Data) -> Void) {
        reply(Data())
    }
}
