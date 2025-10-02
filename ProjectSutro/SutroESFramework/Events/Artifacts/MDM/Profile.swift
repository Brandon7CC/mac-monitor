//
//  Profile.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/2/25.
//

import Foundation

/// Models a ``es_profile_t``
/// Ensure Profile conforms to Codable and Equatable
public struct Profile: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID()
    
    public var identifier: String
    public var uuid: String
    
    public var organization: String
    public var display_name: String
    public var scope: String
    
    /// ``es_profile_source_t``
    public var install_source: Int16
    public var install_source_string: String
    
    // Ignore id from being decoded
    enum CodingKeys: String, CodingKey {
        case identifier
        case uuid
        case install_source
        case install_source_string
        case organization
        case display_name
        case scope
    }
    
    public func toString() -> String {
        return "[Scope: \(scope)]  Name: \(display_name), ID: \(identifier)"
    }
    
    public var installSourceShortName: String {
        return install_source_string.replacingOccurrences(of: "ES_PROFILE_SOURCE_", with: "")
    }
    
    public init(from profile: es_profile_t) {
        self.identifier = profile.identifier.toString() ?? ""
        self.uuid = profile.uuid.toString() ?? ""
        self.organization = profile.organization.toString() ?? ""
        self.display_name = profile.display_name.toString() ?? ""
        self.scope = profile.scope.toString() ?? ""
        
        self.install_source = Int16(profile.install_source.rawValue)
        switch profile.install_source {
        case ES_PROFILE_SOURCE_MANAGED:
            self.install_source_string = "ES_PROFILE_SOURCE_MANAGED"
        case ES_PROFILE_SOURCE_INSTALL:
            self.install_source_string = "ES_PROFILE_SOURCE_INSTALL"
        default:
            self.install_source_string = "UNKNOWN"
        }
    }
}
