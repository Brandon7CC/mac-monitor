//
//  StreamReply.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Reply
/// The Security Extension's answer to a ``StreamRequest``.
///
/// Every field but the version, status and Security Extension version may be missing, and an unknown status reads as
/// ``Status-swift.enum/unsupported``, so a newer Security Extension's reply still reads. A field added later must be
/// optional for the same reason.
public struct StreamReply: XPCReply, Equatable, Sendable {
    /// How the request went.
    public enum Status: String, Codable, Sendable, XPCFailureStatus {
        /// Done.
        case ok
        /// Not a stream request, too large, or asking for a stream that can't be.
        case invalid
        /// A newer request than this Security Extension understands.
        case unsupported
        /// The caller isn't root.
        case refused
        /// The connection has already streamed: one stream a connection.
        case alreadyStreaming
        /// ``SensorXPC/maxCommandLineStreams`` streams are already running.
        case sessionLimit
        /// Endpoint Security refused a client: the system has too many.
        case clientLimit
        /// Endpoint Security refused a client: the Security Extension lacks Full Disk Access.
        case notPermitted
        /// Endpoint Security refused the stream for another reason.
        case failed
    }
    
    /// The newest request version the Security Extension understands (``StreamRequest/currentVersion``).
    public var version: Int
    /// How the request went.
    public var status: Status
    /// What went wrong, as a sentence, for every status but ``Status-swift.enum/ok``.
    public var problem: String?
    /// The Security Extension's version, such as "2.2.0 (1)".
    public var sensorVersion: String
    /// The stream that started, for a stream request.
    public var stream: StreamStarted?
    /// What the stream delivered and lost, for a stop request.
    public var summary: StreamSummary?
    
    private enum CodingKeys: String, CodingKey {
        case version, status, problem, sensorVersion, stream, summary
    }
    
    /// - Parameters:
    ///   - status: How the request went.
    ///   - problem: What went wrong.
    ///   - sensorVersion: The Security Extension's version.
    ///   - stream: The stream that started.
    ///   - summary: What the stream delivered and lost.
    public init(_ status: Status, problem: String? = nil, sensorVersion: String, stream: StreamStarted? = nil,
                summary: StreamSummary? = nil) {
        version = StreamRequest.currentVersion
        self.status = status
        self.problem = problem
        self.sensorVersion = sensorVersion
        self.stream = stream
        self.summary = summary
    }
    
    /// Read a reply, tolerating a newer Security Extension's.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: A `DecodingError` for a missing version, status or Security Extension version.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        status = Status(rawValue: try container.decode(String.self, forKey: .status)) ?? .unsupported
        problem = try container.decodeIfPresent(String.self, forKey: .problem)
        sensorVersion = try container.decode(String.self, forKey: .sensorVersion)
        stream = try container.decodeIfPresent(StreamStarted.self, forKey: .stream)
        summary = try container.decodeIfPresent(StreamSummary.self, forKey: .summary)
    }
}


// MARK: - Started
/// The stream a ``StreamRequest/Kind-swift.enum/stream`` request started.
public struct StreamStarted: Codable, Equatable, Sendable {
    /// The `ES_EVENT_TYPE_NOTIFY_*` names subscribed, in order.
    public var events: [String]
    /// How many saved mutes apply, or `nil` for a stream without them (`--no-mutes`).
    public var savedMutes: Int?
    
    /// - Parameters:
    ///   - events: The `ES_EVENT_TYPE_NOTIFY_*` names subscribed.
    ///   - savedMutes: How many saved mutes apply, or `nil` without them.
    public init(events: [String], savedMutes: Int?) {
        self.events = events
        self.savedMutes = savedMutes
    }
}


// MARK: - Summary
/// What a stream delivered and lost, as the Security Extension counted it when it stopped.
///
/// `macmonitor` counts every `global_seq_num` gap it sees. Of those, ``droppedByEndpointSecurity`` were lost before
/// they reached the Security Extension, and the rest while `macmonitor` was behind: dropped with the buffer full
/// (``droppedWhileBehind``), or skipped while capture was paused (``skippedWhilePaused``).
public struct StreamSummary: Codable, Equatable, Sendable {
    /// Events the Security Extension serialized for the stream.
    public var captured: Int
    /// Events in batches `macmonitor` replied to.
    public var delivered: Int
    /// Messages Endpoint Security dropped before handing them to the stream's clients.
    public var droppedByEndpointSecurity: Int
    /// Events dropped with the stream's buffer full.
    public var droppedWhileBehind: Int
    /// Messages the stream's clients were handed while capture was paused, and skipped.
    public var skippedWhilePaused: Int
    /// How many times capture paused until `macmonitor` caught up.
    public var pauses: Int
    
    /// - Parameters:
    ///   - captured: Events serialized for the stream.
    ///   - delivered: Events `macmonitor` replied to.
    ///   - droppedByEndpointSecurity: Messages Endpoint Security dropped.
    ///   - droppedWhileBehind: Events dropped with the buffer full.
    ///   - skippedWhilePaused: Messages skipped while capture was paused.
    ///   - pauses: How many times capture paused.
    public init(captured: Int, delivered: Int, droppedByEndpointSecurity: Int, droppedWhileBehind: Int,
                skippedWhilePaused: Int, pauses: Int) {
        self.captured = captured
        self.delivered = delivered
        self.droppedByEndpointSecurity = droppedByEndpointSecurity
        self.droppedWhileBehind = droppedWhileBehind
        self.skippedWhilePaused = skippedWhilePaused
        self.pauses = pauses
    }
}
