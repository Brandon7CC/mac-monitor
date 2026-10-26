//
//  Profile.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/2/25.
//

import Foundation

/// Models a ``es_profile_t``
public struct Profile: Codable, Equatable, Hashable {
    public var identifier: String
    public var uuid: String
    
    /// ``es_profile_source_t``
    public var install_source: Int16
    public var install_source_string = ""
    
    public var organization: String
    public var display_name: String
    public var scope: String
    
    public func toString() -> String {
        return "[Scope: \(scope)]  Name: \(display_name), ID: \(identifier)"
    }
    
    public var installSourceShortName: String {
        return install_source_string.replacingOccurrences(of: "ES_PROFILE_SOURCE_", with: "")
    }
    
    public init(from profile: es_profile_t) {
        self.identifier = profile.identifier.string ?? ""
        self.uuid = profile.uuid.string ?? ""
        self.organization = profile.organization.string ?? ""
        self.display_name = profile.display_name.string ?? ""
        self.scope = profile.scope.string ?? ""
        
        self.install_source = Int16(profile.install_source.rawValue)
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension Profile: ESEnrichable {
    /// Derive the install source's name.
    public mutating func enrich() {
        switch es_profile_source_t(rawValue: UInt32(truncatingIfNeeded: install_source)) {
        case ES_PROFILE_SOURCE_MANAGED:
            self.install_source_string = "ES_PROFILE_SOURCE_MANAGED"
        case ES_PROFILE_SOURCE_INSTALL:
            self.install_source_string = "ES_PROFILE_SOURCE_INSTALL"
        default:
            self.install_source_string = "UNKNOWN"
        }
    }
}
