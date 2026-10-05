//
//  MuteRequest.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Request
/// A request about the saved mute set, from Mac Monitor or `macmonitor`, as JSON over XPC.
///
/// Import and Export happen in the caller: it reads a file into entries and sends `.replace` or `.add`, and writes
/// the entries of a reply to a file. The Security Extension only ever reads entries, never a file or a path to one.
public struct MuteRequest: XPCRequest, Equatable, Sendable {
    /// The version of requests and replies this Mac Monitor sends and understands.
    public static let currentVersion: Int = 1
    /// The largest request: as large as a mute file.
    public static let maximumSize: Int = MuteLimits.maxFileBytes
    /// What the request is, for messages.
    public static let noun = "mute request"
    
    /// What to do with the saved mute set.
    public enum Operation: String, Codable, Sendable {
        /// Reply with the saved set.
        case list
        /// Mute more: merge the request's mutes into the saved set.
        case add
        /// Unmute: remove each entry's events, or its path when it names none.
        case remove
        /// Make the saved set exactly the request's mutes. Unmute all is a replace with none.
        case replace
        /// Make the saved set Mac Monitor's default set (``MuteList/shippedDefault``).
        case reset
    }
    
    /// The request's version.
    public var version: Int
    /// What to do.
    public var operation: Operation
    /// The mutes to add, remove, or replace the set with.
    public var mutes: [MuteFile.Entry]
    
    private enum CodingKeys: String, CodingKey {
        case version, operation, mutes
    }
    
    /// - Parameters:
    ///   - operation: What to do.
    ///   - mutes: The mutes to add, remove, or replace the set with.
    public init(_ operation: Operation, _ mutes: [MuteFile.Entry] = []) {
        version = Self.currentVersion
        self.operation = operation
        self.mutes = mutes
    }
    
    /// Read the version, then the operation as a name, so a newer request is reported as unsupported rather than
    /// as malformed.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: ``XPCRequestError`` for a version below 1 or newer than this build's, or an unknown operation, or a
    ///   `DecodingError`.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        (version, operation) = try Self.header(of: container, version: .version, name: .operation)
        mutes = try container.decodeIfPresent([MuteFile.Entry].self, forKey: .mutes) ?? []
    }
    
    /// Why some JSON isn't a mute request, as a mute file's problems are worded.
    ///
    /// - Parameter error: The decoding error.
    /// - Returns: Such as ": “mutes.2.path” is missing".
    public static func invalidReason(_ error: Error) -> String {
        ": \(MuteFile.reason(error))"
    }
}


// MARK: - Reply
/// The Security Extension's answer to a ``MuteRequest``: always the saved set as it stands after the request.
public struct MuteReply: XPCReply, Equatable, Sendable {
    /// How the request went.
    public enum Status: String, Codable, Sendable, XPCFailureStatus {
        /// Done, or nothing to do.
        case ok
        /// The caller may only read the saved set: another Mac Monitor owns the event stream.
        case refused
        /// The caller may only read the saved set: the user running Mac Monitor isn't an administrator.
        case notAdministrator
        /// A mute in the request can't be used.
        case invalid
        /// The saved set was written by a newer Mac Monitor: it can only be reset.
        case readOnly
        /// The saved set couldn't be written, so nothing changed.
        case storageFailed
        /// A newer request than this Security Extension understands.
        case unsupported
    }
    
    /// The reply's version.
    public var version: Int
    /// How the request went.
    public var status: Status
    /// Did the saved set change?
    public var changed: Bool
    /// The saved set after the request, in canonical order.
    public var mutes: [MuteFile.Entry]
    /// Why the request was refused or invalid, and what was left out of it, as sentences.
    public var problems: [String]
    /// Something to tell the user about the saved set: it was recovered from a damaged file, or is read-only.
    public var notice: String?
    /// What the caller may do with the saved set, or `nil` if the Security Extension didn't say (or said something
    /// this build doesn't know).
    public var access: MuteAccess?
    
    private enum CodingKeys: String, CodingKey {
        case version, status, changed, mutes, problems, notice, access
    }
    
    /// - Parameters:
    ///   - status: How the request went.
    ///   - changed: Did the saved set change?
    ///   - mutes: The saved set after the request.
    ///   - problems: Why the request was refused or invalid, and what was left out of it.
    ///   - notice: Something to tell the user about the saved set.
    ///   - access: What the caller may do with the saved set.
    public init(status: Status, changed: Bool = false, mutes: [MuteFile.Entry], problems: [String] = [],
                notice: String? = nil, access: MuteAccess? = nil) {
        version = MuteRequest.currentVersion
        self.status = status
        self.changed = changed
        self.mutes = mutes
        self.problems = problems
        self.notice = notice
        self.access = access
    }
    
    /// Everything but the version and status may be missing, an unknown status reads as ``Status/unsupported``, and
    /// an unknown access as none, so a newer Security Extension's reply still reads.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: A `DecodingError` for a missing version or status.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        status = Status(rawValue: try container.decode(String.self, forKey: .status)) ?? .unsupported
        changed = try container.decodeIfPresent(Bool.self, forKey: .changed) ?? false
        mutes = try container.decodeIfPresent([MuteFile.Entry].self, forKey: .mutes) ?? []
        problems = try container.decodeIfPresent([String].self, forKey: .problems) ?? []
        notice = try container.decodeIfPresent(String.self, forKey: .notice)
        access = try container.decodeIfPresent(String.self, forKey: .access).flatMap(MuteAccess.init(rawValue:))
    }
}


// MARK: - Change
/// A change to the saved mute set, as the Security Extension hands it to every session that follows the set, and
/// tells every `macmonitor stream` that does.
public struct MuteSetChange: XPCReply, Equatable, Sendable {
    /// Who changed it, such as "Mac Monitor (pid 123)" or "macmonitor (pid 4211)". The process ID is only a hint.
    public var caller: String
    /// Mutes for paths and types the set didn't have.
    public var added: Int
    /// Mutes the set lost.
    public var removed: Int
    /// Mutes whose events changed.
    public var changed: Int
    /// How many mutes the set has now.
    public var mutes: Int
    
    /// - Parameters:
    ///   - caller: Who changed it.
    ///   - added: Mutes for paths and types the set didn't have.
    ///   - removed: Mutes the set lost.
    ///   - changed: Mutes whose events changed.
    ///   - mutes: How many mutes the set has now.
    public init(caller: String, added: Int, removed: Int, changed: Int, mutes: Int) {
        self.caller = caller
        self.added = added
        self.removed = removed
        self.changed = changed
        self.mutes = mutes
    }
    
    /// - Parameters:
    ///   - caller: Who changed it.
    ///   - difference: How the set changed.
    ///   - mutes: How many mutes it has now.
    public init(by caller: String, _ difference: MuteListDifference, mutes: Int) {
        self.init(caller: caller, added: difference.added.count, removed: difference.removed.count,
                  changed: difference.changed.count, mutes: mutes)
    }
}
