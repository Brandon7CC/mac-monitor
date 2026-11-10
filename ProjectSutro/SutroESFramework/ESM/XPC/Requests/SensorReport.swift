//
//  SensorReport.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/9/26.
//

import Foundation


// MARK: - Report
/// What the Security Extension says of itself, for `macmonitor status`: whether Endpoint Security lets it make a
/// client, and who is capturing through it. It answers a ``StreamRequest/Kind-swift.enum/status`` request, which any
/// `macmonitor` may send: it reads state and changes nothing.
///
/// A field added later must be optional, as a ``StreamReply``'s are.
public struct SensorReport: Codable, Equatable, Sendable {
    /// What Endpoint Security answers when the Security Extension asks for a client.
    public enum EndpointSecurity: String, Codable, Sendable {
        /// It may: the Security Extension has what it needs, Full Disk Access included.
        case ok
        /// It lacks Full Disk Access (TCC).
        case notPermitted
        /// It isn't entitled to Endpoint Security.
        case notEntitled
        /// The system already has as many clients as it allows.
        case tooManyClients
        /// It was refused for another reason.
        case failed

        /// - Parameter result: What `es_new_client` returned, as Mac Monitor names it.
        public init(_ result: NewClientResult) {
            switch result {
            case .success: self = .ok
            case .notPermitted: self = .notPermitted
            case .notEntitled: self = .notEntitled
            case .tooManyClients: self = .tooManyClients
            default: self = .failed
            }
        }

        /// A name a newer Security Extension sends that this build doesn't know reads as ``failed``.
        ///
        /// - Parameter decoder: The decoder.
        /// - Throws: A `DecodingError` when the value isn't a string.
        public init(from decoder: Decoder) throws {
            self = Self(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .failed
        }
    }

    /// Mac Monitor, the app, as the Security Extension sees it.
    public struct App: Codable, Equatable, Sendable {
        /// Is a Mac Monitor connected, and the owner of the event stream?
        public var connected: Bool
        /// Is it recording?
        public var recording: Bool

        /// - Parameters:
        ///   - connected: Is a Mac Monitor connected, and the owner of the event stream?
        ///   - recording: Is it recording?
        public init(connected: Bool, recording: Bool) {
            self.connected = connected
            self.recording = recording
        }
    }

    /// What Endpoint Security answers when the Security Extension asks for a client.
    public var endpointSecurity: EndpointSecurity
    /// Mac Monitor, the app.
    public var app: App
    /// How many `macmonitor` streams are running.
    public var streams: Int
    /// The most `macmonitor` streams at once.
    public var streamCapacity: Int

    /// - Parameters:
    ///   - endpointSecurity: What Endpoint Security answers when the Security Extension asks for a client.
    ///   - app: Mac Monitor, the app.
    ///   - streams: How many `macmonitor` streams are running.
    ///   - streamCapacity: The most at once.
    public init(endpointSecurity: EndpointSecurity, app: App, streams: Int, streamCapacity: Int) {
        self.endpointSecurity = endpointSecurity
        self.app = app
        self.streams = streams
        self.streamCapacity = streamCapacity
    }
}
