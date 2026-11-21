//
//  IndicatorPackRequirement.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation
import Security
import CryptoKit


// MARK: - Indicator pack requirement
/// Who must have signed a pack, in the code signing requirement language (step 3 of ``IndicatorPackVerifier``),
/// evaluated against the signer's chain as SecTrust built it, leaf first.
///
/// A release's pack must be signed with a Developer ID Application certificate of ``SensorXPC/teamID``
/// (``developerID``), the clauses ``SensorXPC`` pins Mac Monitor's connections to, without the signing identifier:
/// (1) `anchor apple generic`: the chain ends at one of Apple's roots (AND)
/// (2) `certificate 1[field.1.2.840.113635.100.6.2.6]`: the certificate that issued the signer's is a Developer ID CA
/// (AND)
/// (3) `certificate leaf[field.1.2.840.113635.100.6.1.13]`: the signer's certificate is a Developer ID Application
/// one (AND)
/// (4) `certificate leaf[subject.OU]`: its Team ID
///
/// A test anchors (1) at its own root instead (``developerID(team:anchoredAt:)``), and keeps (2) to (4).
///
/// The requirement is evaluated with `SecRequirementEvaluate`, which evaluates one against a certificate chain alone,
/// with no code to check. Security exports it but declares it only in a private header (`SecRequirementPriv.h`), so
/// it's looked up once by name. Without it, nothing is accepted (``IndicatorPackError/cannotCheckSigner``). It checks
/// only the certificates' fields and the anchor's hash, so the chain it's given must be one SecTrust built.
public struct IndicatorPackRequirement: Equatable, Sendable {
    /// The requirement in the code signing requirement language.
    public let text: String
    /// The Team ID it requires, for saying whose a refused certificate is.
    public let teamID: String

    /// What a release's pack must be signed by: Swiftly Detecting's Developer ID Application certificate.
    public static let developerID = IndicatorPackRequirement(team: SensorXPC.teamID)

    /// A Developer ID Application certificate of a team, (1) to (4) above.
    ///
    /// - Parameters:
    ///   - team: The Team ID.
    ///   - anchor: The clause the chain's anchor must meet: `anchor apple generic` for Apple's roots.
    public init(team: String, anchor: String = "anchor apple generic") {
        text = anchor + " and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
            + " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
            + " and certificate leaf[subject.OU] = \"\(team)\""
        teamID = team
    }

    /// A Developer ID Application certificate of a team whose chain ends at a root of one's own, rather than one of
    /// Apple's: for tests, which have no Developer ID identity.
    ///
    /// - Parameters:
    ///   - team: The Team ID.
    ///   - root: The root the chain must end at.
    /// - Returns: The requirement, `certificate root = H"<root's SHA-1>"` in place of `anchor apple generic`.
    public static func developerID(team: String, anchoredAt root: SecCertificate) -> IndicatorPackRequirement {
        let hash = Insecure.SHA1.hash(data: SecCertificateCopyData(root) as Data)
        let hex = hash.withUnsafeBytes { ESLogger.hex(bytes: $0) }
        return IndicatorPackRequirement(team: team, anchor: "certificate root = H\"\(hex)\"")
    }

    /// Does a chain meet the requirement?
    ///
    /// - Parameter chain: The signer's chain, leaf first and anchor last, as SecTrust built it.
    /// - Returns: `true` when it does.
    /// - Throws: ``IndicatorPackError/cannotCheckSigner`` when the requirement can't be made or evaluated.
    func isMet(by chain: [SecCertificate]) throws(IndicatorPackError) -> Bool {
        var requirement: SecRequirement?
        guard let evaluate = SPI.evaluate,
              SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement else { throw .cannotCheckSigner }
        switch evaluate(requirement, chain as CFArray, nil, []) {
        case errSecSuccess: return true
        case errSecCSReqFailed: return false
        default: throw .cannotCheckSigner
        }
    }

    /// Refuse a chain that doesn't meet the requirement, saying whose it is.
    ///
    /// - Parameter chain: The signer's chain, leaf first and anchor last, as SecTrust built it.
    /// - Throws: ``IndicatorPackError/wrongTeam(found:expected:)`` for a signer's certificate of another team,
    ///   ``IndicatorPackError/notDeveloperID`` for one of this team that doesn't meet it otherwise, and
    ///   ``IndicatorPackError/cannotCheckSigner`` when it can't be evaluated.
    func check(_ chain: [SecCertificate]) throws(IndicatorPackError) {
        guard try !isMet(by: chain) else { return }
        let team = chain.first.flatMap(IndicatorPackCertificate.init)?.organizationalUnit
        guard team == teamID else { throw .wrongTeam(found: team, expected: teamID) }
        throw .notDeveloperID
    }

    /// Security's private calls, each looked up once.
    private enum SPI {
        /// `SecRequirementEvaluate(requirement, certificateChain, context, flags)`.
        typealias Evaluate = @convention(c) (SecRequirement, CFArray, CFDictionary?, SecCSFlags) -> OSStatus

        /// Security, which this framework links.
        static let handle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY)
        /// `SecRequirementEvaluate`, or `nil` when it isn't exported.
        static let evaluate = handle.flatMap { dlsym($0, "SecRequirementEvaluate") }
            .map { unsafeBitCast($0, to: Evaluate.self) }
    }
}
