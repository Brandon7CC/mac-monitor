//
//  SavedIndicatorSetPackLoadingTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/16/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Loading an installed pack
/// Pins how the Security Extension loads an installed indicator pack when it starts: it's the baseline again, its
/// signature is checked again but for its certificate's dates, a pack that can't be used or that stopped the last
/// load is moved aside, and one no later than the release the build links in is removed.
final class SavedIndicatorSetPackLoadingTests: XCTestCase {
    private var directory: URL!
    /// The indicators the build links in.
    private var linked: [Indicator] = []

    /// A fresh directory, and the linked indicators.
    ///
    /// - Throws: If the directory can't be created or a fixture is missing.
    override func setUpWithError() throws {
        try super.setUpWithError()
        directory = try makeIndicatorDirectory()
        linked = try linkedFixtures()
    }

    /// A loaded set in the test's directory that trusts the fixtures' signer, as the Security Extension starting
    /// again makes one.
    ///
    /// - Parameters:
    ///   - sequence: Which release the build links in: none unless given.
    ///   - clock: The time its verifier says.
    /// - Returns: The set.
    /// - Throws: If it can't be made.
    private func started(sequence: Int = 0, clock: Date = XCTestCase.packClock) throws -> SavedIndicatorSet {
        let set = try makeSavedIndicatorSet(in: directory, defaults: linked, sequence: sequence,
                                            verifier: try packVerifier(clock: clock))
        set.load()
        return set
    }

    /// Install release 2 into the test's directory.
    ///
    /// - Returns: The reply to the install.
    /// - Throws: If the set can't be made or the fixture is missing.
    @discardableResult
    private func installRelease() throws -> IndicatorReply {
        let reply = try started().send(IndicatorRequest(.installPack, pack: try releaseFixture(2).file))
        XCTAssertEqual(reply.status, .ok, reply.failure ?? "")
        return reply
    }

    /// The pack's file name.
    private let packName = IndicatorPackFile.installedLayout.fileName

    /// An installed pack is the baseline again after a restart, with the set as it was left, and nothing to tell.
    func testAnInstalledPackIsTheBaselineAfterARestart() throws {
        let installed = try installRelease()
        let reply = try started().send(IndicatorRequest(.list))
        XCTAssertEqual(reply, installed.listed)
        XCTAssertEqual(reply.pack?.source, .installed)
        XCTAssertEqual(reply.pack?.sequence, 2)
        XCTAssertNil(reply.notice)
        XCTAssertEqual(names(in: directory), ["indicator-pack.json", "indicators.json"], "No marker is left")
    }

    /// A change made after a pack is installed is saved against the pack, and read back against it.
    func testAChangeAfterInstallingIsSavedAgainstThePack() throws {
        try installRelease()
        let pack = try releaseFixture(2).pack
        let set = try started()
        XCTAssertEqual(set.send(IndicatorRequest(.remove, ids: [pack.indicators[1].id])).status, .ok)
        XCTAssertEqual(set.send(IndicatorRequest(.setEnabled, ids: [pack.indicators[2].id], enabled: true)).status,
                       .ok)
        var on = pack.indicators[2]
        on.isEnabled = true
        XCTAssertEqual(try started().send(IndicatorRequest(.list)).indicators, [pack.indicators[0], on])
    }

    /// An installed pack keeps loading after its signer's certificate expires: it was verified when it was installed.
    /// The same pack isn't installed then.
    func testAnInstalledPackLoadsAfterItsCertificateExpires() throws {
        try installRelease()
        let later = Self.packDate("2047-01-01T00:00:00Z")
        let set = try started(clock: later)
        let reply = set.send(IndicatorRequest(.list))
        XCTAssertEqual(reply.pack?.sequence, 2)
        XCTAssertNil(reply.notice)
        let refused = set.send(IndicatorRequest(.installPack, pack: try releaseFixture(3).file))
        XCTAssertEqual(refused.status, .invalid)
        XCTAssertEqual(refused.failure?.contains("expired"), true, refused.failure ?? "")
    }

    /// A pack file that was changed, isn't a pack, or isn't the Security Extension's to trust is moved aside. The
    /// build's indicators apply, the set saved against the pack reads against them, and the notice says where the
    /// file went.
    func testAPackThatCannotBeUsedIsMovedAside() throws {
        let changed = try packFile("indicator-pack-2.json") { object in
            guard var bytes = (object["payload"] as? String).flatMap({ Data(base64Encoded: $0) }) else { return }
            bytes[bytes.count / 2] ^= 1
            object["payload"] = bytes.base64EncodedString()
        }
        let files = [changed, Data("nope".utf8), try fixture("indicator-pack-not-developer-id.json"),
                     try fixture("indicator-pack.json")]
        for file in files {
            directory = try makeIndicatorDirectory()
            try installRelease()
            try writeIndicatorFile(file, named: packName, in: directory)
            let reply = try started().send(IndicatorRequest(.list))
            XCTAssertEqual(reply.pack, IndicatorPackStatus(sequence: 0, source: .linked, mode: .notify))
            XCTAssertEqual(reply.indicators, linked)
            XCTAssertEqual(reply.baseline, linked)
            let moved = directory.appendingPathComponent(IndicatorPackFile.installedLayout.unreadableFileName).path
            XCTAssertEqual(reply.notice?.hasPrefix("The installed indicator pack couldn't be used. "), true,
                           reply.notice ?? "")
            XCTAssertEqual(reply.notice?.hasSuffix("""
                It was moved to \(moved). The indicators this Mac Monitor came with apply.
                """), true, reply.notice ?? "")
            XCTAssertEqual(names(in: directory), ["indicator-pack.unreadable.json", "indicators.json"])
            XCTAssertNil(try started().send(IndicatorRequest(.list)).notice, "It's told once")
        }
    }

    /// A loading marker left behind means the last load of the pack stopped the Security Extension: the pack is
    /// moved aside rather than tried again, and the saved set is kept.
    func testAPackWhoseLoadNeverFinishedIsMovedAside() throws {
        try installRelease()
        try writeIndicatorFile(Data(), named: IndicatorPackFile.loadingLayout.fileName, in: directory)
        let reply = try started().send(IndicatorRequest(.list))
        XCTAssertEqual(reply.pack?.source, .linked)
        XCTAssertEqual(reply.indicators, linked)
        XCTAssertEqual(reply.notice?.hasPrefix("""
            The installed indicator pack couldn't be used. The Security Extension stopped while it loaded it.
            """), true, reply.notice ?? "")
        XCTAssertEqual(names(in: directory),
                       ["indicator-pack.unreadable.json", "indicator-updates.json", "indicators.json"],
                       "It counted against the pack, which is kept")
    }

    /// A build that links in a release as late as the installed one, or later, removes the installed pack: its own
    /// indicators are the baseline.
    func testABuildWithALaterReleaseRemovesTheInstalledPack() throws {
        for sequence in [2, 5] {
            directory = try makeIndicatorDirectory()
            try installRelease()
            let reply = try started(sequence: sequence).send(IndicatorRequest(.list))
            XCTAssertEqual(reply.pack, IndicatorPackStatus(sequence: sequence, source: .linked, linked: sequence,
                                                           mode: .notify))
            XCTAssertEqual(reply.indicators, linked)
            XCTAssertNil(reply.notice)
            XCTAssertEqual(names(in: directory), ["indicators.json"])
        }
    }

    /// With no pack installed, nothing about one is said or left behind.
    func testNoInstalledPackIsTheBuildsIndicators() throws {
        let reply = try started().send(IndicatorRequest(.list))
        XCTAssertEqual(reply.pack, IndicatorPackStatus(sequence: 0, source: .linked, mode: .notify))
        XCTAssertEqual(reply.baseline, linked)
        XCTAssertNil(reply.notice)
        XCTAssertEqual(names(in: directory), ["indicators.json"])
    }
}


// MARK: - Replies
private extension IndicatorReply {
    /// The reply as a list says it: nothing changed.
    var listed: IndicatorReply {
        var reply = self
        reply.changed = false
        return reply
    }
}
