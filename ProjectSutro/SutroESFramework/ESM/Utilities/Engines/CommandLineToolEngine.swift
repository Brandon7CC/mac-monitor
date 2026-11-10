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
    /// Any caller may ask, so it goes on a connection of its own (``SensorClient/probe(caller:_:completion:)``): a
    /// Security Extension older than 3.1.0 closes the connection that asks, which mustn't be the one that owns the
    /// event stream.
    ///
    /// - Parameter completion: Called on the main thread with the level, or `nil` if the Security Extension couldn't
    ///   be reached or doesn't know the call.
    public func commandLineAccess(completion: @escaping (CommandLineAccess?) -> Void) {
        sensor.probe { $0.commandLineAccess(reply: $1) } completion: { level in
            completion(level.flatMap(CommandLineAccess.init(rawValue:)))
        }
    }

    /// Ask the Security Extension to change who may use `macmonitor` without `sudo` (agent context).
    ///
    /// Only the connection that owns the event stream may, while there is one, so it goes on Mac Monitor's own, once
    /// the Security Extension running now has said it knows the call (``commandLineAccessSupport``).
    ///
    /// - Parameters:
    ///   - access: The new level.
    ///   - completion: Called on the main thread. `.unavailable` if the Security Extension couldn't be reached or
    ///     doesn't know the call.
    public func setCommandLineAccess(_ access: CommandLineAccess,
                                     completion: @escaping (CommandLineAccessChange) -> Void) {
        let sensor = sensor
        commandLineAccessSupport.send({ answer in
            sensor.call { $0.setCommandLineAccess(access.rawValue, reply: $1) } completion: { answer($0) }
        }, completion: { status in
            completion(status.flatMap(CommandLineAccessChange.init(rawValue:)) ?? .unavailable)
        })
    }

    /// Ask the Security Extension running now who may use `macmonitor` without `sudo`, on a connection of its own,
    /// for ``commandLineAccessSupport``.
    ///
    /// - Parameter answered: Called on the main queue: `true` when it replied.
    internal func probeCommandLineAccess(_ answered: @escaping (Bool) -> Void) {
        sensor.probe { $0.commandLineAccess(reply: $1) } completion: { answered($0 != nil) }
    }
}
