//
//  CommandLineToolEngine.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/6/26.
//

import Foundation


extension EndpointSecurityManager {
    // MARK: Command line tool
    /// Ask the Security Extension to install or remove `/usr/local/bin/macmonitor` (agent context).
    ///
    /// - Parameters:
    ///   - plan: The change Settings offered.
    ///   - authorization: An administrator's approval (``CommandLineToolAuthorization/requestApproval(prompt:)``).
    ///   - completion: Called on the main thread. `.unavailable` if the Security Extension couldn't be reached.
    public func changeCommandLineTool(_ plan: CommandLineToolLink.Plan, authorization: Data,
                                      completion: @escaping (CommandLineToolLinker.Outcome) -> Void) {
        sensor.call {
            $0.changeCommandLineTool(action: plan.action.rawValue, tool: plan.tool, expected: plan.expected,
                                     authorization: authorization, reply: $1)
        } completion: { status in
            completion(status.flatMap(CommandLineToolLinker.Outcome.init(rawValue:)) ?? .unavailable)
        }
    }
}


extension EndpointSecurityManager {
    // MARK: Command line access
    /// Ask the Security Extension who may use `macmonitor` without `sudo` (agent context).
    ///
    /// - Parameter completion: Called on the main thread with the level, or `nil` if the Security Extension couldn't
    ///   be reached.
    public func commandLineAccess(completion: @escaping (CommandLineAccess?) -> Void) {
        sensor.call { $0.commandLineAccess(reply: $1) } completion: { level in
            completion(level.flatMap(CommandLineAccess.init(rawValue:)))
        }
    }

    /// Ask the Security Extension to change who may use `macmonitor` without `sudo` (agent context).
    ///
    /// - Parameters:
    ///   - access: The new level.
    ///   - completion: Called on the main thread. `.unavailable` if the Security Extension couldn't be reached.
    public func setCommandLineAccess(_ access: CommandLineAccess,
                                     completion: @escaping (CommandLineAccessChange) -> Void) {
        sensor.call { $0.setCommandLineAccess(access.rawValue, reply: $1) } completion: { status in
            completion(status.flatMap(CommandLineAccessChange.init(rawValue:)) ?? .unavailable)
        }
    }
}
