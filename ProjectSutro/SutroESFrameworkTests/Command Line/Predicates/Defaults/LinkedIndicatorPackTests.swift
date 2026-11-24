//
//  LinkedIndicatorPackTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The linked indicator pack
/// Pins `SutroESFramework/Indicators/LinkedIndicatorPack.json`, the signed pack a build links in: the framework's
/// binary holds it, it's signed as a release is, its indicators are ``Indicator/defaults``, and its release is the
/// one an installed pack must be later than. Every indicator in it runs in this build, and it has the ones Mac
/// Monitor's own code names.
///
/// `ProjectSutro/Scripts/Generate/link-indicator-pack.sh` copies a newer signed pack in.
final class LinkedIndicatorPackTests: XCTestCase {
    /// The committed file.
    static var fileURL: URL {
        repositoryURL.appendingPathComponent("ProjectSutro/SutroESFramework/Indicators/LinkedIndicatorPack.json")
    }

    /// The framework's binary holds the committed file, byte for byte: a stale or missing section fails.
    func testBinaryHoldsTheCommittedFile() throws {
        XCTAssertEqual(LinkedIndicatorPack.embedded(), try Data(contentsOf: Self.fileURL))
    }

    /// The committed file is one the Security Extension would load as an installed pack: signed with Swiftly
    /// Detecting's Developer ID over exactly its payload. Its certificate's dates aren't checked, as they aren't
    /// for a pack already installed, so the test doesn't expire with the certificate.
    func testTheFileIsSignedAsAReleaseIs() throws {
        let file = try Data(contentsOf: Self.fileURL)
        let verified = try IndicatorPackVerifier().verify(file, .loading)
        XCTAssertEqual(verified.signer.teamID, SensorXPC.teamID)
        XCTAssertEqual(verified.payload, try IndicatorPackFile(file).payload)
        XCTAssertEqual(try IndicatorPack.decode(verified.payload), LinkedIndicatorPack.pack)
    }

    /// The indicators Mac Monitor ships are the pack's, and the baseline a Mac starts from is the pack: its release,
    /// when and what it was built from, and the identities it retires. A pack installed later must be a later
    /// release.
    func testDefaultsAndTheBaselineAreThePack() throws {
        let pack = LinkedIndicatorPack.pack
        XCTAssertEqual(Indicator.defaults, pack.indicators)
        XCTAssertEqual(Indicator.retiredDefaults, Set(pack.pack.retired))
        let linked = IndicatorBaseline.linked
        XCTAssertEqual(linked.source, .linked)
        XCTAssertGreaterThan(linked.sequence, 0)
        XCTAssertEqual(linked.sequence, pack.pack.sequence)
        XCTAssertEqual(linked.indicators, pack.indicators)
        XCTAssertEqual(linked.commit, pack.pack.commit)
        XCTAssertEqual(linked.published, pack.pack.published)
        XCTAssertEqual(linked.retired, Set(pack.pack.retired))
        XCTAssertEqual(linked.status(linked: linked.sequence).needsNewer, 0)
        let payload = try IndicatorPackFile(Data(contentsOf: Self.fileURL)).payload
        XCTAssertThrowsError(try linked.replacement(from: payload)) { error in
            XCTAssertEqual(error as? IndicatorPackRefusal,
                           .notNewer(offered: linked.sequence, current: linked.sequence, source: .linked))
        }
    }

    /// Every indicator of the pack runs in this build: none needs a newer Mac Monitor, and the Security Extension
    /// compiles each. Each has a revision, which its hits carry.
    func testEveryLinkedIndicatorRuns() {
        XCTAssertTrue(LinkedIndicatorPack.pack.newer.isEmpty)
        XCTAssertTrue(Indicator.defaults.allSatisfy(\.isSupported))
        XCTAssertTrue(Indicator.defaults.allSatisfy { ($0.revision ?? 0) > 0 })
        XCTAssertEqual(Set(Indicator.defaults.map(\.id)).count, Indicator.defaults.count)
        let compiled = CompiledIndicators(Indicator.defaults, defaults: CompiledIndicators.shippedDefaults,
                                          pack: IndicatorBaseline.linked.sequence)
        XCTAssertEqual(compiled.problems.map(\.reason), [])
    }

    /// The pack has the indicators Mac Monitor's own code names, which its header lists as core. New executable's
    /// predicate, which its mark, Event Facts' clock and Event Search's starter search share, has the age the
    /// clock counts to.
    func testThePackHasTheIndicatorsTheCodeNames() {
        XCTAssertFalse(Indicator.builtInMarks.isEmpty)
        XCTAssertEqual(Indicator.shipped(9).name, "New executable")
        XCTAssertTrue(LinkedIndicatorPack.pack.pack.core.contains(Indicator.uuid(9)))
        let age = Int(ESProcessExecEvent.newExecutableAge * 1000)
        XCTAssertTrue(Indicator.newExecutablePredicate.contains("event.exec.executable_age_ms < \(age)"),
                      Indicator.newExecutablePredicate)
    }

    /// No shipped indicator or built-in mark has a retired identity, and every one Mac Monitor numbered itself is
    /// known as its own.
    func testRetiredIdentitiesAreNeverGivenAgain() {
        let shipped = (Indicator.defaults + Indicator.builtInMarks).map(\.id)
        XCTAssertFalse(Indicator.retiredDefaults.isEmpty)
        XCTAssertTrue(Indicator.retiredDefaults.isDisjoint(with: shipped))
        XCTAssertTrue(Indicator.retiredDefaults.allSatisfy(Indicator.isShippedIdentity))
        XCTAssertTrue(Indicator.builtInMarks.map(\.id).allSatisfy(Indicator.isShippedIdentity))
        XCTAssertFalse(Indicator.isShippedIdentity(UUID()))
    }

    /// A file that isn't a signed pack's, a payload that isn't a pack, and a pack that isn't a release aren't used.
    func testUnusableFilesAreRefused() throws {
        let file = try Data(contentsOf: Self.fileURL)
        XCTAssertEqual(try LinkedIndicatorPack.decode(file), LinkedIndicatorPack.pack)
        XCTAssertThrowsError(try LinkedIndicatorPack.decode(Data("[]".utf8)))
        XCTAssertThrowsError(try LinkedIndicatorPack.decode(try IndicatorPackFile(file).payload),
                             "The payload alone isn't the signed file")
        let signed = try JSONSerialization.jsonObject(with: IndicatorPackFile(file).payload)
        var payload = try XCTUnwrap(signed as? [String: Any])
        var header = try XCTUnwrap(payload["pack"] as? [String: Any])
        header["sequence"] = 0
        payload["pack"] = header
        let unreleased = try packFile(payload: JSONSerialization.data(withJSONObject: payload), signature: Data([1]))
        XCTAssertThrowsError(try LinkedIndicatorPack.decode(unreleased)) { error in
            XCTAssertEqual((error as? LinkedIndicatorPack.Problem)?.description,
                           "It isn't a release: its sequence is 0.")
        }
    }
}
