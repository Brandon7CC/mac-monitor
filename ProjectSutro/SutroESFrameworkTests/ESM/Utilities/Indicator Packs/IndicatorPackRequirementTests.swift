//
//  IndicatorPackRequirementTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
import CryptoKit
@testable import SutroESFramework


// MARK: - Who must sign a pack
/// Pins the requirement a release's pack is checked against, and that `SecRequirementEvaluate` evaluates it on a
/// chain the way code signing does: Mac Monitor 3.1's own signing chain (public certificates, from
/// `codesign --extract-certificates`) meets it, and a chain of another team, a chain missing its Developer ID CA, and
/// the fixtures' chain to a throwaway root don't.
final class IndicatorPackRequirementTests: XCTestCase {
    /// The fixtures' chain, as SecTrust builds it from their signature with their root as the only anchor.
    ///
    /// - Returns: The chain, leaf first.
    /// - Throws: If the fixture can't be read or its signature doesn't verify.
    private func fixtureChain() throws -> [SecCertificate] {
        let file = try IndicatorPackFile(try fixture("indicator-pack.json"))
        let signature = try IndicatorPackSignature(file.signature, over: file.payload)
        let evaluation = IndicatorPackTrust(anchors: [try packRoot()]).evaluate(signature, .loading,
                                                                                 at: Self.packClock)
        XCTAssertNil(evaluation.failure)
        return evaluation.chain
    }

    /// The release requirement is the design's, byte for byte: Developer ID certificates and Swiftly Detecting's
    /// team.
    func testTheReleaseRequirementIsUnchanged() {
        XCTAssertEqual(IndicatorPackRequirement.developerID.text, """
            anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate \
            leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "4HMJQ7V3SX"
            """)
        XCTAssertEqual(IndicatorPackRequirement.developerID.teamID, SensorXPC.teamID)
    }

    /// The requirement is the one Mac Monitor's connections are pinned to, without the signing identifier.
    func testItIsSensorXPCsDeveloperIDRequirementWithoutAnIdentifier() {
        let identifier = "com.swiftlydetecting.agent"
        let pinned = SensorXPC.developerIDRequirement(for: identifier)
        XCTAssertEqual(pinned.replacingOccurrences(of: " and identifier \"\(identifier)\"", with: ""),
                       IndicatorPackRequirement.developerID.text)
    }

    /// A test's requirement differs only in its anchor: the root's SHA-1, in uppercase hex, in place of Apple's
    /// roots.
    func testATestRequirementOnlyChangesTheAnchor() throws {
        let test = IndicatorPackRequirement.developerID(team: "4HMJQ7V3SX", anchoredAt: try packRoot())
        let hash = Insecure.SHA1.hash(data: try fixture("indicator-pack-root.cer")).map { String(format: "%02X", $0) }
        XCTAssertEqual(test.text, IndicatorPackRequirement.developerID.text
            .replacingOccurrences(of: "anchor apple generic", with: "certificate root = H\"\(hash.joined())\""))
        XCTAssertEqual(test.teamID, "4HMJQ7V3SX")
    }

    /// Mac Monitor 3.1's signing chain meets the release requirement, and not another team's. A chain without its
    /// Developer ID CA, or without Apple's root, doesn't.
    func testMacMonitorsSigningChainMeetsTheReleaseRequirement() throws {
        let chain = try releaseChain()
        XCTAssertTrue(try IndicatorPackRequirement.developerID.isMet(by: chain))
        XCTAssertNoThrow(try IndicatorPackRequirement.developerID.check(chain))

        let other = IndicatorPackRequirement(team: Self.packTeam)
        XCTAssertFalse(try other.isMet(by: chain))
        XCTAssertEqual(thrown(IndicatorPackError.self) { try other.check(chain) },
                       .wrongTeam(found: "4HMJQ7V3SX", expected: Self.packTeam))
        for partial in [[chain[0], chain[2]], [chain[0], chain[1]], [chain[0]]] {
            XCTAssertFalse(try IndicatorPackRequirement.developerID.isMet(by: partial), "\(partial.count)")
        }
    }

    /// The fixtures' chain meets a requirement anchored at their root, and not one anchored at Apple's roots, for
    /// either team. Mac Monitor's chain doesn't meet one anchored at the test root.
    func testTheTestRootStandsInForApplesRoots() throws {
        let root = try packRoot()
        let chain = try fixtureChain()
        XCTAssertEqual(chain.count, 3)
        XCTAssertTrue(try IndicatorPackRequirement.developerID(team: Self.packTeam, anchoredAt: root).isMet(by: chain))
        XCTAssertFalse(try IndicatorPackRequirement(team: Self.packTeam).isMet(by: chain))
        XCTAssertFalse(try IndicatorPackRequirement.developerID.isMet(by: chain))
        XCTAssertFalse(try IndicatorPackRequirement.developerID(team: "4HMJQ7V3SX", anchoredAt: root)
            .isMet(by: try releaseChain()))
    }

    /// A requirement that doesn't parse can't check anyone, so nothing passes it.
    func testARequirementThatDoesntParseRefusesEveryone() throws {
        let broken = IndicatorPackRequirement(team: Self.packTeam, anchor: "anchor (")
        XCTAssertEqual(thrown(IndicatorPackError.self) { try broken.isMet(by: try releaseChain()) }, .cannotCheckSigner)
    }
}
