//
//  IndicatorPackTrustTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Trusting a signer's chain
/// Pins how a signer's chain is trusted against the system's anchors, on Mac Monitor 3.1's own signing chain (public
/// certificates, which expire on February 1, 2027 with the Developer ID CA that issued them): trusted while it's
/// valid, refused as expired after when installing, and still trusted after when loading at startup, however wrong
/// the clock.
///
/// Loading never asks the network, so these run offline, and revocation is what trustd already knows.
final class IndicatorPackTrustTests: XCTestCase {
    /// Mac Monitor 3.1's signing chain as a signature carries it: the Developer ID CA and Apple's root beside the
    /// signer's certificate.
    ///
    /// - Returns: The signature's certificates, as `CMSDecoder` would give them.
    /// - Throws: An `XCTest` failure if a fixture is missing.
    private func releaseSignature() throws -> IndicatorPackSignature {
        let chain = try releaseChain()
        return IndicatorPackSignature(signer: chain[0], certificates: Array(chain.dropFirst()))
    }

    /// The release chain is trusted by the system's anchors while it's valid, all the way to Apple's root.
    func testTheReleaseChainIsTrustedWhileValid() throws {
        let evaluation = IndicatorPackTrust(anchors: nil).evaluate(try releaseSignature(), .loading,
                                                                   at: Self.packDate("2026-11-11T18:44:37Z"))
        XCTAssertNil(evaluation.failure)
        XCTAssertEqual(evaluation.chain.count, 3)
        XCTAssertEqual(evaluation.chain.compactMap(IndicatorPackCertificate.init).map(\.commonName),
                       ["Developer ID Application: Brandon Dalton (4HMJQ7V3SX)", "Developer ID Certification Authority",
                        "Apple Root CA"])
        XCTAssertTrue(try IndicatorPackRequirement.developerID.isMet(by: evaluation.chain))
    }

    /// After the chain expires, loading still trusts it: as of the day the signing certificate was issued, a year
    /// on, and with a clock reset to 1970.
    func testLoadingTrustsTheReleaseChainAfterItExpires() throws {
        let signature = try releaseSignature()
        for clock in ["2028-01-01T00:00:00Z", "2040-01-01T00:00:00Z", "1970-01-01T00:00:00Z"].map(Self.packDate) {
            let evaluation = IndicatorPackTrust(anchors: nil).evaluate(signature, .loading, at: clock)
            XCTAssertNil(evaluation.failure, "\(clock)")
            XCTAssertTrue(try IndicatorPackRequirement.developerID.isMet(by: evaluation.chain), "\(clock)")
        }
    }

    /// Installing refuses the release chain once it expires, naming the signing certificate and the day.
    func testInstallingRefusesTheReleaseChainOnceItExpires() throws {
        let clock = Self.packDate("2027-03-01T00:00:00Z")
        let evaluation = IndicatorPackTrust(anchors: nil).evaluate(try releaseSignature(), .installing, at: clock)
        let expiry = Self.packDate("2027-02-01T22:12:15Z")
        let signer = "Developer ID Application: Brandon Dalton (4HMJQ7V3SX)"
        XCTAssertEqual(evaluation.failure, .expired(certificate: signer, on: expiry, clock: clock))
    }

    /// Certificates the signature carries don't make a root trusted: the fixtures' chain, carrying its own root, is
    /// refused by the system's anchors in both modes, and by no anchors at all.
    func testACarriedRootIsntAnAnchor() throws {
        let file = try IndicatorPackFile(try fixture("indicator-pack.json"))
        let signature = try IndicatorPackSignature(file.signature, over: file.payload)
        XCTAssertEqual(signature.certificates.count, 3, "the leaf, the CA and the root")
        for anchors in [nil, []] as [[SecCertificate]?] {
            for mode in [IndicatorPackVerifier.Mode.installing, .loading] {
                let failure = IndicatorPackTrust(anchors: anchors).evaluate(signature, mode, at: Self.packClock).failure
                guard case .untrusted = failure else { return XCTFail("\(mode): \(String(describing: failure))") }
            }
        }
        XCTAssertNil(IndicatorPackTrust(anchors: [try packRoot()]).evaluate(signature, .installing,
                                                                            at: Self.packClock).failure)
    }

    /// A certificate's validity includes both of its dates.
    func testValidityIncludesBothDates() throws {
        let certificate = try XCTUnwrap(IndicatorPackCertificate(try certificateFixture("indicator-pack-signer.cer")))
        XCTAssertEqual(certificate.notBefore, Self.packDate("2026-01-01T00:00:00Z"))
        XCTAssertEqual(certificate.notAfter, Self.packDate("2046-01-01T00:00:00Z"))
        XCTAssertEqual(certificate.organizationalUnit, Self.packTeam)
        XCTAssertEqual(certificate.commonName, Self.packSignerName)
        XCTAssertTrue(certificate.isValid(at: certificate.notBefore))
        XCTAssertTrue(certificate.isValid(at: certificate.notAfter))
        XCTAssertNil(certificate.lapse(at: certificate.notAfter))
        XCTAssertFalse(certificate.isValid(at: certificate.notBefore.addingTimeInterval(-1)))
        XCTAssertFalse(certificate.isValid(at: certificate.notAfter.addingTimeInterval(1)))
    }
}
