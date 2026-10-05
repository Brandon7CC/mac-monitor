//
//  StreamProtocol.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - StreamProtocol
/// Exported by the Security Extension (sensor) to `macmonitor`, and only on connections from root
/// (``SensorListenerRouter``).
///
/// A connection streams at most once. A ``StreamRequest/Kind-swift.enum/stream`` request starts the connection's own
/// capture session (one Endpoint Security client per event class), whose events arrive through the
/// ``StreamReaderProtocol`` `macmonitor` exports. `macmonitor` replies to each batch once it has written it, which is
/// the stream's back-pressure. The stream ends with a ``StreamRequest/Kind-swift.enum/stop`` request or with the
/// connection.
///
/// Requests and replies are versioned JSON, like ``MuteRequest``.
@objc public protocol StreamProtocol {
    /// Answer one request.
    ///
    /// - Parameters:
    ///   - request: A JSON encoded ``StreamRequest``, at most ``StreamRequest/maximumSize`` bytes.
    ///   - reply: A JSON encoded ``StreamReply``.
    func perform(_ request: Data, reply: @escaping (Data) -> Void)
    
    /// Read or change the saved mute set, as Mac Monitor does through ``SensorProtocol/mutes(_:reply:)``. Root may
    /// always change it.
    ///
    /// - Parameters:
    ///   - request: A JSON encoded ``MuteRequest`` (at most ``MuteLimits/maxFileBytes``).
    ///   - reply: A JSON encoded ``MuteReply``.
    func mutes(_ request: Data, reply: @escaping (Data) -> Void)
}


// MARK: - Request
/// A request from `macmonitor` to the Security Extension, as JSON over XPC.
///
/// **Versions:** a field added later is optional and keeps the version, so an older Security Extension ignores it and
/// a newer one reads its absence as the old behavior. Renaming or removing a field, or changing what one means, bumps
/// ``currentVersion``. A Security Extension answers a newer version, or a kind it doesn't know, with
/// ``StreamReply/Status-swift.enum/unsupported`` and its own version, so `macmonitor` can say which side is out of
/// date (``XPCRequest``).
public struct StreamRequest: XPCRequest, Equatable, Sendable {
    /// The version of requests and replies this build sends and understands.
    public static let currentVersion: Int = 1
    /// The largest request the Security Extension reads. A stream request names at most
    /// ``StreamPlan/maximumEvents`` events, well under this.
    public static let maximumSize: Int = 64 * 1024
    /// What the request is, for messages.
    public static let noun = "stream request"
    
    /// What to do.
    public enum Kind: String, Codable, Sendable {
        /// Reply with the Security Extension's version, and do nothing else.
        case hello
        /// Start the connection's stream with ``StreamRequest/options``.
        case stream
        /// Stop the stream: no new events, every event already captured is delivered, and the reply carries the
        /// ``StreamSummary``.
        case stop
    }
    
    /// The request's version.
    public var version: Int
    /// What to do.
    public var kind: Kind
    /// The stream to start, for ``Kind-swift.enum/stream``.
    public var options: StreamOptions?
    
    private enum CodingKeys: String, CodingKey {
        case version, kind, options
    }
    
    /// - Parameters:
    ///   - kind: What to do.
    ///   - options: The stream to start, for ``Kind-swift.enum/stream``.
    public init(_ kind: Kind, options: StreamOptions? = nil) {
        version = Self.currentVersion
        self.kind = kind
        self.options = options
    }
    
    /// Read the version, then the kind as a name, so a newer request is reported as unsupported rather than as
    /// malformed.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: ``XPCRequestError`` for a version below 1 or newer than this build's, or an unknown kind, or a
    ///   `DecodingError`.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        (version, kind) = try Self.header(of: container, version: .version, name: .kind)
        options = try container.decodeIfPresent(StreamOptions.self, forKey: .options)
    }
}


// MARK: - Options
/// The stream a ``StreamRequest/Kind-swift.enum/stream`` request asks for, before the Security Extension validates it
/// (``StreamPlan``).
public struct StreamOptions: Codable, Equatable, Sendable {
    /// `ES_EVENT_TYPE_NOTIFY_*` names. None means Mac Monitor's default subscriptions.
    public var events: [String]
    /// Apply the saved mute set, and follow its changes? `macmonitor stream --no-mutes` sends `false`.
    public var appliesSavedMutes: Bool
    
    private enum CodingKeys: String, CodingKey {
        case events, appliesSavedMutes
    }
    
    /// - Parameters:
    ///   - events: `ES_EVENT_TYPE_NOTIFY_*` names, or none for the defaults.
    ///   - appliesSavedMutes: Apply the saved mute set?
    public init(events: [String] = [], appliesSavedMutes: Bool = true) {
        self.events = events
        self.appliesSavedMutes = appliesSavedMutes
    }
    
    /// Missing events mean the defaults, and missing `appliesSavedMutes` means `true`: a stream applies the saved set
    /// unless it says otherwise.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: A `DecodingError` for a field of the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        events = try container.decodeIfPresent([String].self, forKey: .events) ?? []
        appliesSavedMutes = try container.decodeIfPresent(Bool.self, forKey: .appliesSavedMutes) ?? true
    }
}

