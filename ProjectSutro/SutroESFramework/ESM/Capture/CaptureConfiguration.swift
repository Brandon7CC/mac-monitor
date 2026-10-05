//
//  CaptureConfiguration.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import EndpointSecurity


// MARK: - Configuration
/// What a ``CaptureSession`` subscribes to and mutes.
public struct CaptureConfiguration {
    /// The events to subscribe to. Only the NOTIFY events Mac Monitor models (`supportedEvents`) are kept; anything
    /// else (an AUTH event, an unknown name read as `ES_EVENT_TYPE_LAST`) is left out and logged.
    public var events: [es_event_type_t]
    /// The path mutes for every client: the saved mute set, or none. Endpoint Security's own default mutes come with
    /// each new client either way.
    public var mutes = MuteList()
    /// Mute this process on every client, as eslogger mutes itself, so that what the session's own process does (such
    /// as spooling events to disk) never feeds back into the capture.
    public var mutesSelf: Bool = true
    /// Names the session in the log, such as "Mac Monitor".
    public var label: String
    
    /// - Parameters:
    ///   - events: The events to subscribe to.
    ///   - label: Names the session in the log.
    public init(events: [es_event_type_t] = defaultEventSubscriptions, label: String) {
        self.events = events
        self.label = label
    }
}


// MARK: - Events
/// One event leaving a capture session.
public struct CapturedEvent {
    /// The event's JSON serialization of `Message`, as Mac Monitor receives it.
    public let json: Data
    /// The client that delivered it.
    public let eventClass: EventClass
}


// MARK: - Start errors
/// Why a capture session couldn't start. Every client it had created is deleted by then.
public enum CaptureStartError: Error, Equatable {
    /// `es_new_client` refused the client for a class, such as when the system has too many clients.
    case clientRefused(EventClass, NewClientResult)
    /// `es_subscribe` failed for a class's client.
    case subscriptionFailed(EventClass)
    
    /// The `start` reply for Mac Monitor: the refusal, or `.internalSubsystem` for a failed subscription (as before).
    public var clientResult: NewClientResult {
        switch self {
        case .clientRefused(_, let result):
            return result
        case .subscriptionFailed:
            return .internalSubsystem
        }
    }
}
