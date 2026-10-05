//
//  MessageSerializer.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import EndpointSecurity


// MARK: - Serializing
/// What a capture lane hands its serializer with each message.
struct LaneContext {
    /// The lane's client.
    let eventClass: EventClass
    /// The Sensor ID to stamp on the event.
    let sensorID: String
    /// The lane's own encoder. Only one thread uses it at a time.
    let encoder: StreamingJSONEncoder
}


/// Turns one Endpoint Security message into the JSON a capture session emits.
///
/// Called on a lane's handler queue: serially within a lane, and concurrently across the lanes of a session (and
/// across sessions), so it must keep no shared mutable state of its own.
protocol EventSerializing {
    /// Serialize one message.
    ///
    /// - Parameters:
    ///   - message: The message. Only valid during the call.
    ///   - lane: The lane's context.
    /// - Returns: The event's JSON, or `nil` if it couldn't be encoded.
    func serialize(_ message: UnsafePointer<es_message_t>, in lane: LaneContext) -> Data?
}


/// Mac Monitor's serializer: builds a `Message` and encodes it as JSON, the one place a capture session pays the
/// per-event build and encode cost.
struct MessageSerializer: EventSerializing {
    /// Signing IDs Apple forces into File Quarantine, read once rather than per event.
    private let forcedQuarantineSigningIDs: [String]
    /// This Mac's macOS version, read when the session starts rather than per event.
    private let macOSVersion: String
    
    /// - Parameters:
    ///   - forcedQuarantineSigningIDs: Signing IDs Apple forces into File Quarantine.
    ///   - macOSVersion: The macOS version to stamp on events.
    init(forcedQuarantineSigningIDs: [String] = ProcessHelpers.forcedQuarantineSigningIDs,
         macOSVersion: String = Message.currentMacOSVersion()) {
        self.forcedQuarantineSigningIDs = forcedQuarantineSigningIDs
        self.macOSVersion = macOSVersion
    }
    
    /// Build the message's `Message`, stamped with the lane's Sensor ID and this Mac's macOS version, and encode it.
    ///
    /// - Parameters:
    ///   - message: The message. Only valid during the call.
    ///   - lane: The lane's context.
    /// - Returns: The JSON, or `nil` if the event couldn't be encoded.
    func serialize(_ message: UnsafePointer<es_message_t>, in lane: LaneContext) -> Data? {
        let event = Message(from: message, sensorID: lane.sensorID, macOS: macOSVersion,
                            forcedQuarantineSigningIDs: forcedQuarantineSigningIDs)
        return try? lane.encoder.encode(event)
    }
}
