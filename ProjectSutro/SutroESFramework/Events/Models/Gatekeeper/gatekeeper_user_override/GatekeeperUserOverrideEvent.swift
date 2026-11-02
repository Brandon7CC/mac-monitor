//
//  GatekeeperUserOverrideEvent.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/18/25.
//

import Foundation
import EndpointSecurity


// MARK: - Gatekeeper User Override event model: https://developer.apple.com/documentation/endpointsecurity/es_event_gatekeeper_user_override_t
// Available beginning in macOS 15.0
public struct GatekeeperUserOverrideEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    /// `es_gatekeeper_user_override_file_type_t`
    public var file_type: Int32
    public var file_type_string = ""
    
    /// File union
    public var file: FilePathUnion
    public var sha256: String?
    
    public var signing_info: SignedFileInfo?
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let gatekeeperOverrideEvent: es_event_gatekeeper_user_override_t = rawMessage.pointee.event.gatekeeper_user_override.pointee
        
        file_type = Int32(gatekeeperOverrideEvent.file_type.rawValue)
        
        file = FilePathUnion.from(override: gatekeeperOverrideEvent)
        self.sha256 = gatekeeperOverrideEvent.sha256.map { ESLogger.hex($0.pointee) }
        signing_info = gatekeeperOverrideEvent.signing_info.map { SignedFileInfo(from: $0.pointee) }
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension GatekeeperUserOverrideEvent: ESEnrichable {
    /// Derive the file type's name.
    public mutating func enrich() {
        switch es_gatekeeper_user_override_file_type_t(rawValue: UInt32(truncatingIfNeeded: file_type)) {
        case ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH:
            file_type_string = "ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH"
        case ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_FILE:
            file_type_string = "ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_FILE"
        default:
            file_type_string = "Unknown"
        }
    }
}
