//
//  MutingEngine.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/7/23.
//

import Foundation
import OSLog

/// Defines constants and  functions for working with path muting at the Endpoint Security level
///
/// Principle is ``applyDefaultMuteSet(client:)`` which takes an ES client and applies the default
/// mute set.
public class MutingEngine {
    
    /// Applies the default mute set to an Endpoint Security client.
    public static func applyDefaultMuteSet(client: OpaquePointer?) {
        _processMuteSet(
            MuteSet.default,
            client: client,
            eventAction: es_mute_path_events,
            globalAction: es_mute_path
        )
    }
    
    /// Unmutes all paths and events defined in the default mute set.
    public static func unmuteDefaultMuteSet(client: OpaquePointer?) {
        _processMuteSet(
            MuteSet.default,
            client: client,
            eventAction: es_unmute_path_events,
            globalAction: es_unmute_path
        )
    }
    
    private static func _processMuteSet(
        _ muteSet: MuteSet,
        client: OpaquePointer?,
        eventAction: (OpaquePointer, UnsafePointer<CChar>, es_mute_path_type_t, UnsafePointer<es_event_type_t>, Int) -> es_return_t,
        globalAction: (OpaquePointer, UnsafePointer<CChar>, es_mute_path_type_t) -> es_return_t
    ) {
        guard let client else { return }
        // Event specific
        for rule in muteSet.eventSpecificRules {
            for path in rule.paths {
                _ = eventAction(client, path, rule.muteType, [rule.eventType], 1)
            }
        }
        
        // Global
        for rule in muteSet.globalRules {
            for path in rule.paths {
                _ = globalAction(client, path, rule.pathType)
            }
        }
    }
}



// MARK: - Path muting XPC operations
/// Extension of the ESM which enables path muting at the ES level.
///
/// **Functionality Covers:**
///   - Getting globally muted paths
///   - Muting a path
///   - Unmuting a path
///   - Reset back to the default mute set
///
extension EndpointSecurityManager {
    // MARK: - Agent Context
    
    public func simpleGetAppleMuteSet() -> [String] { Array(appleMuteSet) }
    
    public func simpleGetMutedPaths() -> [String] {
        return Array(self.globallyMutedPaths.sorted(by: <))
    }
    
    public func requestAppleMuteSet(_ completion: ((Set<String>) -> Void)? = nil) {
        sensor.call { $0.appleMuteSet(reply: $1) } completion: { response in
            guard let response else { return }
            self.appleMuteSet = Set(response)
            completion?(self.appleMuteSet)
        }
    }
    
    // MARK: Step #1 in getting the list of muted paths from Endpoint Security
    public func requestMutedPaths() {
        sensor.call { $0.mutedPaths(reply: $1) } completion: { response in
            guard let response else { return }
            
            // Only keep paths we can decode
            self.globallyMutedPaths = Set(response.filter { jsonPath in
                guard decodePathJSON(pathJSON: jsonPath) != nil else {
                    os_log("Error parsing muted path")
                    return false
                }
                return true
            })
        }
    }
    
    // MARK: Step #2 in muting paths
    // @note send across paths that should be muted by the Endpoint Security client
    public func puntPathToMute(pathToMute: String, muteCase: es_mute_path_type_t, pathEvents: [String]) {
        let type: String = getMuteCaseString(muteType: muteCase)
        sensor.call { $0.setMute(pathToMute, type: type, events: pathEvents, muted: true, reply: $1) }
    }
    
    // MARK: Step #2 in unmuting paths
    public func puntPathToUnmute(pathToUnmute: String, type: String, events: [String]) {
        sensor.call { $0.setMute(pathToUnmute, type: type, events: events, muted: false, reply: $1) }
    }
    
    // MARK: Step #2 in reseting to the default mute set
    public func resetMuteSetToDefault() {
        sensor.call { $0.resetMutes(reply: $1) }
    }
    
    
    
    // MARK: - Sensor Context
    
    /// Every path currently muted on the ES client.
    ///
    /// - Returns: JSON serializations of ``ESMutedPath``. Empty when there is no ES client.
    public func seGetGlobalMutedPaths() -> Set<String> {
        guard let esClient = self.esClient else {
            os_log("There is no client to fetch the muted paths from!")
            return []
        }
        
        // Submit the fetch request to endpoint security
        guard let fetchedPaths: UnsafeMutablePointer<es_muted_paths_t> = fetch_muted_paths(esClient) else {
            os_log("The paths we fetched from ES are nil!")
            return []
        }
        defer { release_es_memory(fetchedPaths) }
        
        return Set((0..<fetchedPaths.pointee.count).map { index in
            pathToJSON(value: ESMutedPath(fromRawESPath: fetchedPaths.pointee.paths[index]))
        })
    }
    
    // MARK: Step #3 in (un)muting paths
    /// Mute, or unmute, a path on the ES client.
    ///
    /// - Parameters:
    ///   - path: The path to mute or unmute.
    ///   - type: How `path` is matched.
    ///   - events: `ES_EVENT_TYPE_*` names to scope the request to. Empty means all events.
    ///   - muted: `true` to mute, `false` to unmute.
    /// - Returns: `true` if Endpoint Security accepted the request.
    @discardableResult
    public func setPathMute(_ path: String, type: es_mute_path_type_t, events: [String], muted: Bool) -> Bool {
        guard let esClient = self.esClient else {
            os_log("There is no endpoint security client to submit this (un)muting request to!")
            return false
        }
        guard !path.isEmpty else { return false }
        
        // Convert the listing of Endpoint Security event type strings to es_event_type_t
        let eventTypes: [es_event_type_t] = events.map { eventStringToType(from: $0) }
        let request: es_return_t
        switch (muted, eventTypes.isEmpty) {
        case (true, true):
            request = es_mute_path(esClient, path, type)
        case (true, false):
            request = es_mute_path_events(esClient, path, type, eventTypes, eventTypes.count)
        case (false, true):
            request = es_unmute_path(esClient, path, type)
        case (false, false):
            request = es_unmute_path_events(esClient, path, type, eventTypes, eventTypes.count)
        }
        
        guard request == ES_RETURN_SUCCESS else {
            os_log("Error \(muted ? "muting" : "unmuting") path: \(getMuteCaseString(muteType: type)): \(path)")
            return false
        }
        return true
    }
}
