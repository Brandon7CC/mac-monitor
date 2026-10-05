//
//  MutingEngine.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/7/23.
//

import Foundation
import OSLog


// MARK: - Path muting XPC operations
/// Extension of the ESM which asks the Security Extension to mute and unmute paths (agent context).
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
}
