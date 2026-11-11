//
//  CommandLineAccess.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation


// MARK: - Command line access
/// Who may run `macmonitor stream`, `macmonitor mute` and `macmonitor indicators` without `sudo`: Settings > Command
/// Line > Without sudo.
///
/// The Security Extension stores it (``CommandLineAccessStore``) and decides every `macmonitor` request by it
/// (``grant(forEffectiveUser:)``). Mac Monitor only asks for a change. The `macmonitor` binary decides nothing: the
/// Security Extension still pins every connection to `macmonitor`'s code signature (``SensorListenerRouter``), so only
/// the genuine tool gets this far.
///
/// **Who "without sudo" means:** any user on the Mac, administrator or not, whether or not they're the console user,
/// so `macmonitor` also works over SSH. While it's on, any process any user runs, such as a script or malware, can read
/// every process's events on the Mac (arguments, file paths) through `macmonitor`, without a password.
///
/// **Who may change it:** like the saved mute set and updates, any user's Mac Monitor, administrator or not, while it
/// owns the event stream or nobody does (``MuteAccess/controlsStream(_:owner:)``). No password is asked.
///
/// **Changes** to the saved mute set and the indicator set are persistent configuration that Mac Monitor and every
/// stream follow, so they're a separate, higher level: ``streaming`` lets anyone list and export both, and only
/// ``streamingAndChanges`` lets them change them. Mutes can already blind capture, so indicators share the level.
///
/// **Default:** ``rootOnly``. A stored value that can't be read is ``rootOnly`` too, so it fails closed.
///
/// **Revoking:** a narrower level applies to the next request. A stream already running keeps running until it ends.
public enum CommandLineAccess: String, Codable, CaseIterable, Comparable, Sendable {
    /// Only root: `sudo macmonitor`. The default.
    case rootOnly
    /// Anyone may also stream, and list or export the saved mute set and the indicators, without `sudo`.
    case streaming
    /// Anyone may also change the saved mute set and the indicators without `sudo`.
    case streamingAndChanges

    /// Orders the levels from narrowest to widest, as they're declared.
    ///
    /// - Parameters:
    ///   - lhs: A level.
    ///   - rhs: Another level.
    /// - Returns: Whether `lhs` allows less than `rhs`.
    public static func < (lhs: Self, rhs: Self) -> Bool {
        allCases.firstIndex(of: lhs)! < allCases.firstIndex(of: rhs)!
    }

    /// What a `macmonitor` connection may do.
    ///
    /// - Parameter euid: The peer's effective user ID, from its audit token.
    /// - Returns: ``CommandLineGrant/everything`` for root, else what this level lets anyone do, else a refusal that
    ///   says why.
    public func grant(forEffectiveUser euid: uid_t) -> CommandLineGrant {
        if euid == 0 { return .everything }
        switch self {
        case .rootOnly: return .refused(Self.needsRoot)
        case .streaming: return .streaming
        case .streamingAndChanges: return .everything
        }
    }
}


// MARK: - Refusals
extension CommandLineAccess {
    /// Where it's changed, as `macmonitor` names it.
    static let setting = "Mac Monitor > Settings > Command Line"

    /// Why a caller who isn't root is refused while only root may use `macmonitor`.
    public static let needsRoot = """
        Mac Monitor only lets root stream and change mutes and indicators. Allow them without sudo in \(setting).
        """

    /// Why a caller without `sudo` may list the saved mute set and the indicators but not change them.
    public static let needsChanges = """
        Mac Monitor lets macmonitor stream without sudo, but not change mutes or indicators. Allow that in \(setting).
        """
}


// MARK: - Grant
/// What the Security Extension lets one `macmonitor` request do (``CommandLineAccess``).
public enum CommandLineGrant: Equatable, Sendable {
    /// Nothing, and why, as a sentence for `macmonitor` to print.
    case refused(String)
    /// Stream, ask the Security Extension's version, and list or export the saved mute set and the indicators.
    case streaming
    /// Everything `macmonitor` does, including changes to the saved mute set and the indicators: root, or anyone at
    /// ``CommandLineAccess/streamingAndChanges``.
    case everything

    /// May it stream, or ask the Security Extension's version?
    public var mayStream: Bool {
        if case .refused = self { return false }
        return true
    }

    /// What it may do with the saved mute set and the indicator set: `nil` for nothing, ``MuteAccess/list`` to list
    /// and export them, or ``MuteAccess/write`` to change them too.
    public var savedSetAccess: MuteAccess? {
        switch self {
        case .refused: return nil
        case .streaming: return .list
        case .everything: return .write
        }
    }

    /// Why it's refused, if it is.
    public var refusal: String? {
        if case .refused(let reason) = self { return reason }
        return nil
    }
}
