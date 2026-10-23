//
//  FakePeer.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/22/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Fake peer
/// A connection from one effective user, as the Security Extension reads it, that records what was done to it.
final class FakePeer: PeerConnection {
    let effectiveUserIdentifier: uid_t
    /// What happened, in order: "requirement <...>", then anything a test appends, such as the endpoint that took it.
    var log: [String] = []
    
    /// - Parameter euid: The peer's effective user ID.
    init(euid: uid_t) {
        effectiveUserIdentifier = euid
    }
    
    /// Record the requirement.
    ///
    /// - Parameter requirement: The requirement string.
    func setCodeSigningRequirement(_ requirement: String) {
        log.append("requirement \(requirement)")
    }
}
