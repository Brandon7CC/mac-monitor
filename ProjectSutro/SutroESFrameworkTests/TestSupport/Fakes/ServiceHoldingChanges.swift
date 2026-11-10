//
//  ServiceHoldingChanges.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - A slow Security Extension
/// A 3.1 Security Extension, in the test process, that lists its indicator set at once but never answers a change,
/// as one still compiling and saving a large import would seem to `macmonitor` when its wait runs out. Or it answers
/// each change with one status, such as a Security Extension that doesn't know the change does.
final class ServiceHoldingChanges: NSObject, NSXPCListenerDelegate, StreamProtocol {
    private let listener = NSXPCListener.anonymous()
    /// The set it lists.
    private let indicators: [Indicator]
    /// The changes it got, which it never answers.
    private let changes = Recorded<IndicatorRequest.Operation>()
    /// How it answers a change, or `nil` to never answer one.
    private let answer: IndicatorReply.Status?

    /// Start listening.
    ///
    /// - Parameters:
    ///   - indicators: The set it lists: Mac Monitor's own unless given.
    ///   - answer: How it answers a change, such as ``IndicatorReply/Status/unsupported`` as a Security Extension
    ///     that doesn't know it does, or `nil` to never answer one.
    init(indicators: [Indicator] = Indicator.defaults, answering answer: IndicatorReply.Status? = nil) {
        self.indicators = indicators
        self.answer = answer
        super.init()
        listener.delegate = self
        listener.activate()
    }

    /// Where `macmonitor` connects.
    var endpoint: NSXPCListenerEndpoint {
        listener.endpoint
    }

    /// The changes asked for, in order.
    var heldChanges: [IndicatorRequest.Operation] {
        changes.all
    }

    /// Accept every connection, exporting the stream interface.
    ///
    /// - Parameters:
    ///   - listener: The anonymous listener.
    ///   - connection: The new connection.
    /// - Returns: Always `true`.
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: StreamProtocol.self)
        connection.exportedObject = self
        connection.activate()
        return true
    }

    /// Refuse every stream request as unsupported: no test asks.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - reply: Its answer.
    func perform(_ request: Data, reply: @escaping (Data) -> Void) {
        reply(Data(#"{"version":1,"status":"unsupported","sensorVersion":"3.1.0 (1)"}"#.utf8))
    }

    /// Answer nothing useful: no test asks.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - reply: Its answer.
    func mutes(_ request: Data, reply: @escaping (Data) -> Void) {
        reply(Data())
    }

    /// List the set at once, and record a change, answering it only as ``answer`` says.
    ///
    /// - Parameters:
    ///   - request: A JSON encoded ``IndicatorRequest``.
    ///   - reply: A JSON encoded ``IndicatorReply``: for a list, and for a change when it answers one.
    func indicators(_ request: Data, reply: @escaping (Data) -> Void) {
        guard let decoded = try? IndicatorRequest.decode(request) else { return reply(Data()) }
        guard decoded.operation == .list else {
            changes.append(decoded.operation)
            guard let answer else { return }
            return reply(IndicatorReply(status: answer, indicators: indicators, failure: "Unknown.").encoded())
        }
        reply(IndicatorReply(status: .ok, indicators: indicators, access: .write).encoded())
    }
}
