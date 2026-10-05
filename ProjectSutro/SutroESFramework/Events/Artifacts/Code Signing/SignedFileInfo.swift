//
//  SignedFileInfo.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/18/25.
//


// Ensure SignedFileInfo conforms to Codable and Equatable
public struct SignedFileInfo: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID.buffered()
    
    public var cdhash: String
    /// Optional ("if available in the signing information"): `nil`, eslogger's `null`, when it isn't.
    public var signing_id, team_id: String?
    
    // Ignore id from being decoded
    enum CodingKeys: String, CodingKey {
        case cdhash, signing_id, team_id
    }
    
    public init(from signing_info: es_signed_file_info_t) {
        cdhash = cdhashToString(cdhash: signing_info.cdhash)
        signing_id = signing_info.signing_id.string
        team_id = signing_info.team_id.string
    }
}
