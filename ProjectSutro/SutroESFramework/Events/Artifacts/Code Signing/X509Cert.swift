//
//  X509Cert.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 3/31/25.
//


/// Models an `X509` certificate: its subject summary and SHA-1 thumbprint, identified by the thumbprint.
public struct X509Cert: Identifiable, Codable, Hashable {
    public var summary, thumbprint: String
    
    public var id: String { thumbprint }
}
