//
//  XPCBatchDelivery.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import OSLog


// MARK: - XPC delivery
/// Delivers an ``EventBatcher``'s batches over an XPC connection whose remote object is ``AgentProtocol`` (Security
/// Extension context): Mac Monitor, or `macmonitor`.
///
/// Holds the connection strongly. Its owner releases the batcher when the connection goes away, which breaks the cycle
/// between a connection, its exported object, and the batcher sending to it.
public final class XPCBatchDelivery: EventBatchDelivery {
    /// The reader's connection.
    public let connection: NSXPCConnection
    /// Names the reader in the log.
    private let label: String
    private static let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension",
                                       category: "EventBatcher")
    
    /// - Parameters:
    ///   - connection: The reader's connection, whose remote object interface is ``SensorXPC/agentInterface``.
    ///   - label: Names the reader in the log, such as "Mac Monitor".
    public init(connection: NSXPCConnection, label: String) {
        self.connection = connection
        self.label = label
    }
    
    /// Send a batch through ``AgentProtocol/receive(events:reply:)``.
    ///
    /// NSXPC runs exactly one of the reply block or the proxy's error handler for a message with a reply.
    ///
    /// - Parameters:
    ///   - batch: Serialized events, oldest first.
    ///   - completion: `true` once the reader replied, `false` if the message failed.
    public func deliver(_ batch: [Data], completion: @escaping (Bool) -> Void) {
        /// Only the count: the error handler lives as long as the message, so it mustn't hold the batch.
        let count = batch.count
        let proxy = connection.remoteObjectProxyWithErrorHandler { [label] error in
            Self.logger.error("""
                Failed to deliver \(count) events to \(label, privacy: .public): \
                \(error.localizedDescription, privacy: .public)
                """)
            completion(false)
        }
        guard let reader = proxy as? AgentProtocol else {
            Self.logger.fault("The remote object proxy does not conform to AgentProtocol!")
            return completion(false)
        }
        reader.receive(events: batch) { completion(true) }
    }
}
