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
    ///   - completion: Called on the main thread with what happened. We report `.unavailable` if the Security
    ///     Extension couldn't be reached.
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
