//
//  MutingEngine.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/7/23.
//

import Foundation
import OSLog


// MARK: - Where a request comes from
/// Where a change to the saved mute set was asked for, which decides where its refusals and warnings show.
public enum MuteRequestOrigin: Sendable {
    /// Settings ▸ Path Muting, or the per-event list: shown there (``EndpointSecurityManager/muteProblems``).
    case settings
    /// An event's menu in the main window: shown there (``EndpointSecurityManager/eventMuteProblems``).
    case eventMenu
}


// MARK: - Path muting XPC operations
/// Extension of the ESM which reads and changes the saved mute set, which the Security Extension keeps and applies
/// (agent context).
///
/// **Functionality Covers:**
///   - Getting the saved mute set, and Apple's default mutes
///   - Muting a path
///   - Unmuting a path
///   - Importing, unmuting everything, and resetting to the default mute set
///
/// Every request publishes the saved set the Security Extension replies with (``savedMutes``), along with its notice
/// (``muteNotice``). What the Security Extension refused or left out of a change shows where the change was asked for
/// (``MuteRequestOrigin``).
extension EndpointSecurityManager {
    // MARK: - Agent Context
    
    public func simpleGetAppleMuteSet() -> [String] { Array(appleMuteSet) }
    
    /// Can this Mac Monitor change the saved mute set? Not while another one owns the event stream
    /// (`.streamOwned`), and never once the Security Extension has said its user isn't an administrator
    /// (``savedMutesNeedAdministrator``): it may still list it. Endpoint Security refusing clients (`.tooManyClients`)
    /// leaves no owner, so the change is allowed. The Security Extension decides each change either way.
    public var canChangeSavedMutes: Bool { connectionResult != .streamOwned && !savedMutesNeedAdministrator }
    
    /// Did the Security Extension say only an administrator may change the saved mute set, and this Mac Monitor's
    /// user isn't one?
    public var savedMutesNeedAdministrator: Bool { savedMutesAccess == .standardUser }
    
    /// The saved mute set, as the Security Extension last sent it: by type name, then path.
    ///
    /// - Returns: One muted path per path and type. No events means every event.
    public func simpleGetMutedPaths() -> [ESMutedPath] {
        savedMutes
    }
    
    public func requestAppleMuteSet(_ completion: ((Set<String>) -> Void)? = nil) {
        sensor.call { $0.appleMuteSet(reply: $1) } completion: { response in
            guard let response else { return }
            self.appleMuteSet = Set(response)
            completion?(self.appleMuteSet)
        }
    }
    
    /// Send a request about the saved mute set and publish the set the Security Extension replies with.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - origin: Where it was asked for, which shows what the Security Extension refused or left out.
    ///   - completion: Called on the main queue with the reply, or `nil` if the request failed (it's logged).
    public func requestMutes(_ request: MuteRequest, from origin: MuteRequestOrigin = .settings,
                             completion: ((MuteReply?) -> Void)? = nil) {
        let operation = request.operation.rawValue
        sensor.call { $0.mutes(request.encoded(), reply: $1) } completion: { data in
            guard let reply = data.flatMap(MuteReply.decode) else {
                os_log("The saved mute set request (%{public}@) got no reply.", operation)
                completion?(nil)
                return
            }
            self.savedMutes = reply.mutes.map(ESMutedPath.init)
            self.muteNotice = reply.notice
            if let access = reply.access { self.savedMutesAccess = access }
            /// Refusals and what was left out, shown where the request was made. Each change replaces what the last
            /// one left, so a refusal never shows up later, out of context; a list only adds to it.
            let problems = reply.status == .ok || !reply.problems.isEmpty
                ? reply.problems : ["The Security Extension answered “\(reply.status.rawValue)”."]
            if request.operation != .list || !problems.isEmpty {
                switch origin {
                case .settings: self.muteProblems = problems
                case .eventMenu: self.eventMuteProblems = problems
                }
            }
            completion?(reply)
        }
    }
    
    /// Ask for the saved mute set.
    public func requestMutedPaths() {
        requestMutes(MuteRequest(.list))
    }
    
    /// Add a mute to the saved set. The reply publishes the new set, so there's nothing to ask for afterwards.
    ///
    /// - Parameters:
    ///   - pathToMute: The path, or path prefix.
    ///   - muteCase: How it's matched.
    ///   - pathEvents: `ES_EVENT_TYPE_*` names. None means every event.
    ///   - origin: Where it was asked for, which shows what the Security Extension refused.
    public func puntPathToMute(pathToMute: String, muteCase: es_mute_path_type_t, pathEvents: [String],
                               from origin: MuteRequestOrigin = .settings) {
        let entry = MuteFile.Entry(path: pathToMute, type: getMuteCaseString(muteType: muteCase), events: pathEvents)
        requestMutes(MuteRequest(.add, [entry]), from: origin)
    }
    
    /// Remove a path, or some of its events, from the saved set.
    ///
    /// - Parameters:
    ///   - pathToUnmute: The path, or path prefix.
    ///   - type: The `ES_MUTE_PATH_TYPE_*` name.
    ///   - events: `ES_EVENT_TYPE_*` names to unmute. None removes the path.
    public func puntPathToUnmute(pathToUnmute: String, type: String, events: [String]) {
        requestMutes(MuteRequest(.remove, [MuteFile.Entry(path: pathToUnmute, type: type, events: events)]))
    }
    
    /// Replace the saved set with Mac Monitor's default set.
    ///
    /// - Parameter completion: Called on the main queue with the reply, or `nil` if the request failed.
    public func resetMuteSetToDefault(completion: ((MuteReply?) -> Void)? = nil) {
        requestMutes(MuteRequest(.reset), completion: completion)
    }
    
    /// Empty the saved set.
    ///
    /// - Parameter completion: Called on the main queue with the reply, or `nil` if the request failed.
    public func unmuteAllPaths(completion: ((MuteReply?) -> Void)? = nil) {
        requestMutes(MuteRequest(.replace), completion: completion)
    }
    
    /// Import a mute file's mutes into the saved set.
    ///
    /// - Parameters:
    ///   - imported: What the file holds.
    ///   - replacing: Replace the saved set, or add to it.
    ///   - completion: Called on the main queue with the reply, or `nil` if the request failed.
    public func importMutes(_ imported: MuteImport, replacing: Bool, completion: ((MuteReply?) -> Void)? = nil) {
        requestMutes(MuteRequest(replacing ? .replace : .add, MuteFile(imported.list).mutes), completion: completion)
    }
}
