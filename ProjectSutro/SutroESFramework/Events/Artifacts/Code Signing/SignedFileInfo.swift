//
//  SignedFileInfo.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/18/25.
//


public struct SignedFileInfo: Codable, Hashable {
    public var cdhash: String
    /// Optional ("if available in the signing information"): `nil`, eslogger's `null`, when it isn't.
    public var signing_id, team_id: String?
    
    public init(from signing_info: es_signed_file_info_t) {
        cdhash = ESLogger.hex(signing_info.cdhash)
        signing_id = signing_info.signing_id.string
        team_id = signing_info.team_id.string
    }
}
