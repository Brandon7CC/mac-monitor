//
//  X509Cert.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 3/31/25.
//


/// Models an `X509` certificate
public struct X509Cert: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID.buffered()
    
    public var summary, thumbprint: String
    
    // Ignore id from being decoded
    enum CodingKeys: String, CodingKey {
        case summary, thumbprint
    }
    
    public init(summary: String, thumbprint: String) {
        self.summary = summary
        self.thumbprint = thumbprint
    }
}
