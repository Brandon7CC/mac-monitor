//
//  MuteAccess.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Access
/// What a caller may do with the saved mute set and the Mac's indicator set (``SavedIndicatorSet``), as the Security
/// Extension decides it for each request. The two sets follow one rule.
///
/// Every reply says which (``MuteReply/access``, ``IndicatorReply/access``), so Mac Monitor can disable what it may
/// not do and say why.
public enum MuteAccess: String, Codable, Sendable {
    /// List it, but not change it: another Mac Monitor owns the event stream.
    case read
    /// List and export it, but not change it: `macmonitor` without `sudo`, while Settings lets it stream but not
    /// change mutes and indicators (``CommandLineAccess/streaming``).
    case list
    /// List and change it.
    case write

    /// What a Mac Monitor connection may do. Any user's Mac Monitor may change the saved set, administrator or not,
    /// but like installing an update, only while it owns the event stream or nobody does. Anyone may list it.
    /// `macmonitor` changes it as root, or as any user when Settings allows it (``CommandLineGrant``).
    ///
    /// - Parameters:
    ///   - caller: The connection a request arrived on, if any. Without one, nothing may change.
    ///   - owner: The connection that owns the event stream, or `nil` if nobody does.
    /// - Returns: ``write`` for a connection that controls the stream, else ``read``.
    public static func app(_ caller: AnyObject?, owner: AnyObject?) -> MuteAccess {
        caller != nil && controlsStream(caller, owner: owner) ? .write : .read
    }

    /// Does a Mac Monitor connection control the event stream? It does when it owns the stream, or when nobody does.
    /// The same rule decides who may install an update.
    ///
    /// - Parameters:
    ///   - caller: The connection a request arrived on, if any.
    ///   - owner: The connection that owns the event stream, or `nil` if nobody does.
    /// - Returns: `true` if `caller` is `owner`, or there's no owner.
    public static func controlsStream(_ caller: AnyObject?, owner: AnyObject?) -> Bool {
        owner == nil || caller === owner
    }

    /// Why a change to the saved mute set is refused, as the reply's status and a sentence for Mac Monitor to show.
    public var refusal: (status: MuteReply.Status, problem: String)? {
        refusal(changing: "the saved mute set")
    }

    /// Why a change to a saved set is refused, as the reply's status and a sentence for Mac Monitor to show.
    ///
    /// - Parameter set: Names the set, such as "the indicators".
    /// - Returns: `nil` for ``write``.
    public func refusal(changing set: String) -> (status: MuteReply.Status, problem: String)? {
        switch self {
        case .write:
            return nil
        case .read:
            return (.refused, "Only the Mac Monitor that owns the event stream can change \(set).")
        case .list:
            return (.refused, CommandLineAccess.needsChanges)
        }
    }
}
