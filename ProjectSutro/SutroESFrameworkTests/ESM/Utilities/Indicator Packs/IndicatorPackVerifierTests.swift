//
//  IndicatorPackVerifierTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Verifying a signed indicator pack
/// Pins what the Security Extension accepts as a signed indicator pack: a payload signed once, by a Developer ID
/// Application certificate of the expected team, with a chain to a trusted anchor, valid now when installing and at
/// any time when loading. Everything else is refused for the first step it fails.
///
/// The packs are `generate-indicator-pack-fixtures.sh`'s, signed with LibreSSL by a throwaway CA of team ABCDE12345,
/// whose root the verifier trusts in place of Apple's (``packVerifier(team:clock:)``).
final class IndicatorPackVerifierTests: XCTestCase {
    /// Both modes.
    private static let modes: [IndicatorPackVerifier.Mode] = [.installing, .loading]

    /// A valid pack passes in both modes, with the payload's bytes exactly as signed and the signer's details.
    func testAValidPackPasses() throws {
        let verifier = try packVerifier()
        let expected = IndicatorPackSigner(teamID: Self.packTeam, commonName: Self.packSignerName,
                                           certificateSHA256: try sha256OfFixture("indicator-pack-signer.cer"),
                                           expires: Self.packDate("2046-01-01T00:00:00Z"))
        for mode in Self.modes {
            let pack = try verifier.verify(try fixture("indicator-pack.json"), mode)
            XCTAssertEqual(pack.payload, try fixture("indicator-pack-payload.json"), "\(mode)")
            XCTAssertEqual(pack.signer, expected, "\(mode)")
        }
    }

    /// A payload changed by one bit, by a byte more, or swapped for another, and a signature whose last byte (its
    /// RSA signature) changed, don't verify.
    func testATamperedPayloadFails() throws {
        let verifier = try packVerifier()
        let other = Data(#"{"format": "com.swiftlydetecting.indicators"}"#.utf8)
        let tampered = [
            try packFile(changingBytesOf: "payload") { $0[$0.startIndex + 20] ^= 0x01 },
            try packFile(changingBytesOf: "payload") { $0.append(0x0a) },
            try packFile(changingBytesOf: "payload") { $0 = other },
            try packFile(changingBytesOf: "signature") { $0[$0.endIndex - 1] ^= 0x01 },
        ]
        for (index, file) in tampered.enumerated() {
            for mode in Self.modes {
                XCTAssertEqual(packRefusal(file, mode, by: verifier), .signatureDoesNotVerify, "\(index) \(mode)")
            }
        }
        XCTAssertEqual(IndicatorPackError.signatureDoesNotVerify.message,
                       "The pack's signature doesn't verify, so the pack changed after it was signed.")
    }

    /// A signer whose certificate lacks the Developer ID Application extension is refused, and so is a chain that
    /// meets the Developer ID clauses but ends at the test root when Apple's is required.
    func testASignerThatIsntDeveloperIDFails() throws {
        let root = try packRoot()
        let verifier = try packVerifier()
        let notDeveloperID = try fixture("indicator-pack-not-developer-id.json")
        let notApple = IndicatorPackVerifier(requirement: IndicatorPackRequirement(team: Self.packTeam),
                                             anchors: [root], clock: { Self.packClock })
        for mode in Self.modes {
            XCTAssertEqual(packRefusal(notDeveloperID, mode, by: verifier), .notDeveloperID)
            XCTAssertEqual(packRefusal(try fixture("indicator-pack.json"), mode, by: notApple), .notDeveloperID)
        }
        XCTAssertEqual(IndicatorPackError.notDeveloperID.message,
                       "It isn't signed with a Developer ID Application certificate from Apple.")
    }

    /// A Developer ID Application certificate of another team is refused, naming both teams. The release
    /// requirement refuses the fixtures for their team before it gets to their anchor.
    func testAnotherTeamFails() throws {
        let pack = try fixture("indicator-pack.json")
        let wrongTeam = IndicatorPackError.wrongTeam(found: Self.packTeam, expected: "4HMJQ7V3SX")
        let release = IndicatorPackVerifier(anchors: [try packRoot()], clock: { Self.packClock })
        for mode in Self.modes {
            XCTAssertEqual(packRefusal(pack, mode, by: try packVerifier(team: "4HMJQ7V3SX")), wrongTeam)
            XCTAssertEqual(packRefusal(pack, mode, by: release), wrongTeam)
        }
        XCTAssertEqual(wrongTeam.message, "It's signed by Team ID ABCDE12345, not 4HMJQ7V3SX.")
        XCTAssertEqual(IndicatorPackError.wrongTeam(found: nil, expected: "4HMJQ7V3SX").message,
                       "It's signed by a certificate with no Team ID, not by 4HMJQ7V3SX.")
    }

    /// A signature with two signers is refused, though each signer's signature verifies and one is ours.
    func testTwoSignersFail() throws {
        for mode in Self.modes {
            XCTAssertEqual(packRefusal(try fixture("indicator-pack-two-signers.json"), mode, by: try packVerifier()),
                           .signers(2))
        }
        XCTAssertEqual(IndicatorPackError.signers(2).message, "The pack has 2 signers, and must have exactly one.")
        XCTAssertEqual(IndicatorPackError.signers(0).message, "The pack's signature has no signer.")
    }

    /// A signature that carries its own content is refused. `CMSDecoder` verifies that content, not the detached
    /// payload it's given, and reports the signer valid, so accepting it would return a payload nobody signed.
    func testASignatureWithItsOwnContentFails() throws {
        for mode in Self.modes {
            XCTAssertEqual(packRefusal(try fixture("indicator-pack-attached.json"), mode, by: try packVerifier()),
                           .contentInSignature)
        }
    }

    /// An expired certificate is refused when installing, saying when it expired, and passes when loading at
    /// startup, since a pack verified when it was installed must keep loading.
    func testAnExpiredCertificateFailsWhenInstallingAndPassesAtStartup() throws {
        let verifier = try packVerifier()
        let pack = try fixture("indicator-pack-expired.json")
        let expiry = Self.packDate("2021-01-01T00:00:00Z")
        let expired = IndicatorPackError.expired(certificate: Self.packSignerName, on: expiry, clock: Self.packClock)
        XCTAssertEqual(packRefusal(pack, .installing, by: verifier), expired)
        XCTAssertEqual(expired.errorDescription,
                       "The certificate “\(Self.packSignerName)” expired on \(IndicatorPackError.day(expiry)).")
        XCTAssertNil(expired.hint)

        let loaded = try verifier.verify(pack, .loading)
        XCTAssertEqual(loaded.payload, try fixture("indicator-pack-payload.json"))
        XCTAssertEqual(loaded.signer.expires, expiry)
    }

    /// The clock decides installing. Ahead of the certificate's expiry it's refused as expired, with no hint since
    /// the clock may be right. Behind its issue date it's refused as not yet valid, with a hint about the clock, as
    /// is an expiry when the clock reads before the day this check was written. Loading passes at any of them.
    func testTheClockDecidesInstallingButNotLoading() throws {
        let pack = try fixture("indicator-pack.json")
        let ahead = Self.packDate("2046-06-01T00:00:00Z")
        let behind = Self.packDate("2001-01-01T00:00:00Z")
        let early = Self.packDate("2025-06-01T00:00:00Z")
        let expiry = Self.packDate("2046-01-01T00:00:00Z")
        let cases: [(clock: Date, file: Data, error: IndicatorPackError, hint: Bool)] = [
            (ahead, pack, .expired(certificate: Self.packSignerName, on: expiry, clock: ahead), false),
            (behind, pack, .notYetValid(certificate: Self.packSignerName, from: Self.packDate("2026-01-01T00:00:00Z"),
                                        clock: behind), true),
            (early, try fixture("indicator-pack-expired.json"),
             .expired(certificate: Self.packSignerName, on: Self.packDate("2021-01-01T00:00:00Z"), clock: early), true),
        ]
        for (clock, file, error, hint) in cases {
            let verifier = try packVerifier(clock: clock)
            XCTAssertEqual(packRefusal(file, .installing, by: verifier), error)
            XCTAssertEqual(error.clockLooksWrong, hint, "\(error)")
            XCTAssertEqual(error.hint, hint ? "This Mac's clock says it's \(IndicatorPackError.day(clock)). If that's "
                           + "wrong, set the date and time in System Settings, then try again." : nil)
            XCTAssertEqual(error.recoverySuggestion, error.hint)
            XCTAssertEqual(error.message, [error.errorDescription, error.hint].compactMap { $0 }.joined(separator: " "))
            XCTAssertNoThrow(try verifier.verify(file, .loading), "\(clock)")
        }
    }

    /// A chain to a root that isn't an anchor is refused, though it meets the requirement: when the verifier trusts
    /// the system's anchors, which don't include the test root, and when it trusts none.
    func testAnUntrustedRootFails() throws {
        let requirement = IndicatorPackRequirement.developerID(team: Self.packTeam, anchoredAt: try packRoot())
        let pack = try fixture("indicator-pack.json")
        for anchors in [nil, []] as [[SecCertificate]?] {
            let verifier = IndicatorPackVerifier(requirement: requirement, anchors: anchors, clock: { Self.packClock })
            for mode in Self.modes {
                guard case .untrusted(let reason) = packRefusal(pack, mode, by: verifier) else {
                    return XCTFail("\(String(describing: anchors)) \(mode) wasn't refused as untrusted")
                }
                XCTAssertTrue(reason.contains("Mac Monitor Test Root CA"), reason)
            }
        }
    }
}
