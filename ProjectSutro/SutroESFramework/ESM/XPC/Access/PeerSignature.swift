//
//  PeerSignature.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation
import Security


// MARK: - Peer signature
/// Which of our programs a connecting process is, by its process ID: a routing hint for ``SensorListenerRouter``.
///
/// A process ID can be reused, so this never authorizes anything. The router only uses it to pick a role, then pins
/// the connection to that role's code signing requirement, which NSXPC checks against the peer's audit token on every
/// message. A peer that fooled the hint is cut off on its first message.
public enum PeerSignature {
    /// Does a running process satisfy a requirement?
    ///
    /// - Parameters:
    ///   - requirement: A code signing requirement string, such as ``SensorXPC/commandLineRequirement``.
    ///   - pid: The process's ID.
    /// - Returns: `true` if its dynamic code signature is valid and satisfies `requirement`. Anything that can't be
    ///   checked is `false`.
    public static func satisfies(_ requirement: String, processIdentifier pid: pid_t) -> Bool {
        var code: SecCode?
        var compiled: SecRequirement?
        let attributes = [kSecGuestAttributePid: pid] as CFDictionary
        guard pid > 0, SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString(requirement as CFString, [], &compiled) == errSecSuccess,
              let compiled else { return false }
        return SecCodeCheckValidity(code, [], compiled) == errSecSuccess
    }

    /// Is a connection's peer signed as `macmonitor`? A hint only (see ``PeerSignature``).
    ///
    /// - Parameter connection: An incoming connection.
    /// - Returns: `true` if its process satisfies ``SensorXPC/commandLineRequirement`` right now.
    public static func isCommandLine(_ connection: some PeerConnection) -> Bool {
        satisfies(SensorXPC.commandLineRequirement, processIdentifier: connection.processIdentifier)
    }
}
