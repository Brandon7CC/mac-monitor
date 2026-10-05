//
//  XPCMessage.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Messages
/// JSON that crosses XPC between Mac Monitor, `macmonitor` and the Security Extension: ``MuteRequest``,
/// ``StreamRequest``, and what the Security Extension sends back.
public protocol XPCMessage: Codable {}

extension XPCMessage {
    /// The message as JSON, for XPC.
    ///
    /// - Returns: The JSON. Messages hold only strings, integers and booleans, so encoding can't fail.
    public func encoded() -> Data {
        (try? JSONEncoder().encode(self)) ?? Data()
    }
}


// MARK: - Replies
/// What the Security Extension sends back, read without throwing. Replies read leniently (see ``MuteReply`` and
/// ``StreamReply``), so a newer Security Extension's still read.
public protocol XPCReply: XPCMessage {}

extension XPCReply {
    /// Read a reply.
    ///
    /// - Parameter data: The JSON.
    /// - Returns: The reply, or `nil` if it isn't one.
    public static func decode(_ data: Data) -> Self? {
        try? JSONDecoder().decode(Self.self, from: data)
    }
}


// MARK: - Requests
/// A request the Security Extension reads strictly: no larger than ``maximumSize``, and a version from 1 to
/// ``currentVersion``. A newer version, or one asking for something this build doesn't know, is
/// ``XPCRequestError/unsupported(_:)`` rather than malformed, so the caller can say which side is out of date.
public protocol XPCRequest: XPCMessage {
    /// The version of requests and replies this build sends and understands.
    static var currentVersion: Int { get }
    /// The largest request the Security Extension reads, in bytes, checked before parsing.
    static var maximumSize: Int { get }
    /// What the request is, for messages, such as "mute request".
    static var noun: String { get }
    
    /// Why some JSON isn't a request, for the message.
    ///
    /// - Parameter error: The decoding error.
    /// - Returns: The rest of a sentence after "The request isn't a mute request", such as ": “mutes” is missing",
    ///   or nothing.
    static func invalidReason(_ error: Error) -> String
}

extension XPCRequest {
    /// Say nothing more about why some JSON isn't a request.
    ///
    /// - Parameter error: The decoding error.
    /// - Returns: Nothing.
    public static func invalidReason(_ error: Error) -> String { "" }
    
    /// Read a request.
    ///
    /// - Parameter data: The JSON, checked against ``maximumSize`` before parsing.
    /// - Returns: The request.
    /// - Throws: ``XPCRequestError``.
    public static func decode(_ data: Data) throws -> Self {
        guard data.count <= maximumSize else {
            let size = maximumSize >= 1 << 20 ? "\(maximumSize >> 20) MiB" : "\(maximumSize >> 10) KiB"
            throw XPCRequestError.invalid("The request is larger than \(size).")
        }
        do {
            return try JSONDecoder().decode(Self.self, from: data)
        } catch let error as XPCRequestError {
            throw error
        } catch {
            throw XPCRequestError.invalid("The request isn't a \(noun)\(invalidReason(error)).")
        }
    }
    
    /// Read what comes first in every request: its version, then what it asks for by name.
    ///
    /// - Parameters:
    ///   - container: The request's container.
    ///   - version: The version's key.
    ///   - name: The key of what the request asks for.
    /// - Returns: The version, and what the request asks for.
    /// - Throws: ``XPCRequestError/invalid(_:)`` for a version below 1, ``XPCRequestError/unsupported(_:)`` for a
    ///   newer version or a name this build doesn't know, or a `DecodingError`.
    static func header<Key: CodingKey, Name: RawRepresentable>(of container: KeyedDecodingContainer<Key>,
                                                                version: Key, name: Key) throws -> (Int, Name)
    where Name.RawValue == String {
        let number = try container.decode(Int.self, forKey: version)
        guard number >= 1 else { throw XPCRequestError.invalid("A \(noun) can't be version \(number).") }
        guard number <= currentVersion else {
            throw XPCRequestError.unsupported("A \(noun) of version \(number) comes from a newer Mac Monitor.")
        }
        let text = try container.decode(String.self, forKey: name)
        guard let named = Name(rawValue: text) else {
            throw XPCRequestError.unsupported("This Security Extension doesn't know the \(noun) “\(text)”.")
        }
        return (number, named)
    }
}


// MARK: - Request errors
/// Why the Security Extension couldn't act on a request.
public enum XPCRequestError: Error, Equatable, CustomStringConvertible {
    /// Not a request, too large, or asking for something that can't be done, such as an AUTH event.
    case invalid(String)
    /// A newer version, or something this build doesn't know.
    case unsupported(String)
    
    /// The problem, as a sentence.
    public var description: String {
        switch self {
        case .invalid(let reason), .unsupported(let reason): return reason
        }
    }
    
    /// The reply status for the error.
    ///
    /// - Parameter type: The reply's status type, such as ``MuteReply/Status``.
    /// - Returns: Its `invalid` or `unsupported`.
    public func status<Status: XPCFailureStatus>(as type: Status.Type = Status.self) -> Status {
        switch self {
        case .invalid: return .invalid
        case .unsupported: return .unsupported
        }
    }
}


/// A reply status that can say why a request couldn't be read.
public protocol XPCFailureStatus {
    /// Not a request, or too large.
    static var invalid: Self { get }
    /// A newer version, or something this build doesn't know.
    static var unsupported: Self { get }
}
