//
//  VerifiedIndicatorPack.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Verified indicator pack
/// A pack whose signature ``IndicatorPackVerifier`` accepted: its payload's bytes, exactly as signed, and who signed
/// them. The payload isn't decoded here.
public struct VerifiedIndicatorPack: Equatable, Sendable {
    /// The payload: the pack's JSON, as signed.
    public let payload: Data
    /// Who signed it.
    public let signer: IndicatorPackSigner
}


// MARK: - Indicator pack signer
/// The certificate that signed an accepted pack, as Mac Monitor and `macmonitor` show it.
public struct IndicatorPackSigner: Codable, Equatable, Sendable {
    /// The certificate's Team ID, its subject's organizational unit, such as `4HMJQ7V3SX`.
    public let teamID: String
    /// The certificate's common name, such as `Developer ID Application: Brandon Dalton (4HMJQ7V3SX)`.
    public let commonName: String
    /// The certificate's SHA-256, in lowercase hex.
    public let certificateSHA256: String
    /// When the certificate expires. A pack installed before then keeps loading after it.
    public let expires: Date

    /// - Parameters:
    ///   - teamID: The certificate's Team ID.
    ///   - commonName: The certificate's common name.
    ///   - certificateSHA256: The certificate's SHA-256, in lowercase hex.
    ///   - expires: When the certificate expires.
    public init(teamID: String, commonName: String, certificateSHA256: String, expires: Date) {
        self.teamID = teamID
        self.commonName = commonName
        self.certificateSHA256 = certificateSHA256
        self.expires = expires
    }

    /// The signer a certificate describes.
    ///
    /// - Parameter certificate: The signer's certificate, read.
    init(_ certificate: IndicatorPackCertificate) {
        self.init(teamID: certificate.organizationalUnit ?? "", commonName: certificate.commonName,
                  certificateSHA256: certificate.sha256, expires: certificate.notAfter)
    }
}
