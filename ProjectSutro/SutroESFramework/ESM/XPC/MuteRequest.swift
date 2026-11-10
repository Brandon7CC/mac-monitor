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
    public enum Operation: String, Codable, CaseIterable, Sendable {
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
        /// Merge a newer default set into the saved set, keeping its own changes (``MuteSetUpdate``). Nothing to do
        /// if there's none.
        case update
        /// Don't take in the newer default set offered: Mac Monitor stops asking at launch and never applies it by
        /// itself. Settings > Path Muting and `macmonitor mute update` still offer it.
        case decline
    }
    
    /// The request's version.
    public var version: Int
    /// What to do.
    public var operation: Operation
    /// The mutes to add, remove, or replace the set with.
    public var mutes: [MuteFile.Entry]
    
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
    public var version: Int = MuteRequest.currentVersion
    /// How the request went.
    public var status: Status
    /// Did the saved set change?
    public var changed: Bool = false
    /// The saved set after the request, in canonical order.
    public var mutes: [MuteFile.Entry]
    /// Why the request was refused or invalid, and what was left out of it, as sentences.
    public var problems: [String] = []
    /// Something to tell the user about the saved set: it was recovered from a damaged file, or is read-only.
    public var notice: String?
    /// What the caller may do with the saved set, or `nil` if the Security Extension didn't say (or said something
    /// this build doesn't know).
    public var access: MuteAccess?
    /// A newer default set the saved set hasn't taken in, which ``MuteRequest/Operation/update`` merges, if any.
    public var update: MuteSetUpdate?
    /// The newer default set applied by itself when the saved set loaded, as no one had changed it. Said until the
    /// next change.
    public var applied: MuteSetUpdate?
}


extension MuteReply {
    /// Everything but the version and status may be missing, an unknown status reads as ``Status/unsupported``
    /// (``XPCFailureStatus``), and an unknown access as none, so a newer Security Extension's reply still reads.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: A `DecodingError` for a missing version or status.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        status = try container.decode(Status.self, forKey: .status)
        changed = try container.decodeIfPresent(Bool.self, forKey: .changed) ?? false
        mutes = try container.decodeIfPresent([MuteFile.Entry].self, forKey: .mutes) ?? []
        problems = try container.decodeIfPresent([String].self, forKey: .problems) ?? []
        notice = try container.decodeIfPresent(String.self, forKey: .notice)
        access = try container.decodeIfPresent(String.self, forKey: .access).flatMap(MuteAccess.init(rawValue:))
        update = (try? container.decodeIfPresent(MuteSetUpdate.self, forKey: .update)) ?? nil
        applied = (try? container.decodeIfPresent(MuteSetUpdate.self, forKey: .applied)) ?? nil
    }
}


// MARK: - Update
/// A newer default mute set that the saved set hasn't taken in, because the user has changed the saved set. A saved
/// set still as the default set left it is updated without asking (``MuteSetUpgrade``).
///
/// Mac Monitor offers it once a launch until it's taken in or declined: Update merges it in, Later asks at the next
/// launch, and Don't Update (``MuteRequest/Operation/decline``) stops the asking. Settings > Path Muting offers it
/// until it's taken in, and `macmonitor mute update` takes it in.
public struct MuteSetUpdate: Codable, Equatable, Sendable {
    /// The default set's revision (``MuteSet/currentRevision``), remembered when the user declines it.
    public var revision: Int
    /// The release that last changed the default set, such as "3.1".
    public var release: String
    /// Mutes the update adds.
    public var added: [MuteFile.Entry]
    /// Mutes it removes, as they are now.
    public var removed: [MuteFile.Entry]
    /// Mutes whose events it changes, as they'd be after.
    public var changed: [MuteFile.Entry]
    /// Did the user decline it? Then Mac Monitor doesn't ask at launch.
    public var declined = false
    
    /// Such as "adds 13 mutes, changes 3 and removes 1", leaving out what it doesn't do.
    public var summary: String {
        let parts = [("adds", added.count), ("changes", changed.count), ("removes", removed.count)]
            .filter { $0.1 > 0 }.enumerated()
            .map { index, part in "\(part.0) \(index == 0 ? String.counted(part.1, "mute") : "\(part.1)")" }
        guard let last = parts.last else { return "changes nothing" }
        return parts.count == 1 ? last : parts.dropLast().joined(separator: ", ") + " and " + last
    }
}


extension MuteSetUpdate {
    /// A missing ``declined`` means it wasn't declined.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: A `DecodingError` for a missing or mistyped field other than ``declined``.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        revision = try container.decode(Int.self, forKey: .revision)
        release = try container.decode(String.self, forKey: .release)
        added = try container.decode([MuteFile.Entry].self, forKey: .added)
        removed = try container.decode([MuteFile.Entry].self, forKey: .removed)
        changed = try container.decode([MuteFile.Entry].self, forKey: .changed)
        declined = try container.decodeIfPresent(Bool.self, forKey: .declined) ?? false
    }
    
    /// The update that takes a saved set to its merge.
    ///
    /// - Parameters:
    ///   - saved: The saved set.
    ///   - merged: The saved set with the current default set merged in.
    ///   - revision: The saved set's revision, for the release that changed the default set since.
    init(from saved: MuteList, to merged: MuteList, after revision: Int) {
        let difference = saved.difference(to: merged)
        let entries = { (keys: [MuteList.Key], list: MuteList) in
            keys.compactMap { list.mute(for: $0) }.map(MuteFile.Entry.init)
        }
        self.init(revision: MuteSet.currentRevision, release: MuteSet.release(after: revision),
                  added: entries(difference.added, merged), removed: entries(difference.removed, saved),
                  changed: entries(difference.changed, merged))
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
}


extension MuteSetChange {
    /// - Parameters:
    ///   - caller: Who changed it.
    ///   - difference: How the set changed.
    ///   - mutes: How many mutes it has now.
    public init(by caller: String, _ difference: MuteListDifference, mutes: Int) {
        self.init(caller: caller, added: difference.added.count, removed: difference.removed.count,
                  changed: difference.changed.count, mutes: mutes)
    }
}
