//
//  IndicatorHitPackTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Which rule fired
/// Pins a hit's `revision` and `pack`, which with its identity say which rule fired: the indicator's revision, and
/// the indicator pack this Mac had, for one Mac Monitor ships. The Security Extension's hits name the pack it
/// installed, Mac Monitor's own name the pack it last heard of, and a trace written before either still reads.
final class IndicatorHitPackTests: XCTestCase {
    /// An indicator with a revision.
    ///
    /// - Parameters:
    ///   - name: Its name.
    ///   - revision: Its revision, or `nil` for none.
    /// - Returns: The indicator.
    private func indicator(_ name: String, revision: Int?) -> Indicator {
        var indicator = Indicator(name: name, description: "", symbol: "star", color: .red,
                                  predicate: #"event.exec != nil AND process.executable.path == "/usr/bin/true""#)
        indicator.revision = revision
        return indicator
    }

    /// A shipped indicator's hit has its revision and the pack. One this Mac added has no pack, and its revision
    /// only if it came with one. A build's own indicators aren't a pack, so their hits name none.
    func testAHitNamesItsRevisionAndPack() {
        let shipped = indicator("Shipped", revision: 3), mine = indicator("Mine", revision: nil)
        let defaults = Indicator.byID([shipped])
        let fromPack = IndicatorHit(shipped, against: defaults, pack: 12, evaluatedBy: .securityExtension)
        XCTAssertEqual(fromPack.revision, 3)
        XCTAssertEqual(fromPack.pack, 12)
        let added = IndicatorHit(mine, against: defaults, pack: 12, evaluatedBy: .securityExtension)
        XCTAssertNil(added.revision)
        XCTAssertNil(added.pack)
        XCTAssertFalse(added.isDefault)
        var imported = indicator("Imported", revision: 7)
        imported.id = UUID()
        XCTAssertEqual(IndicatorHit(imported, against: defaults, pack: 12, evaluatedBy: .export).revision, 7)
        let own = IndicatorHit(shipped, against: defaults, evaluatedBy: .securityExtension)
        XCTAssertEqual(own.revision, 3)
        XCTAssertNil(own.pack)
        XCTAssertNil(IndicatorHit(shipped, against: defaults, pack: 0, evaluatedBy: .export).pack)
    }

    /// One this Mac edited keeps the revision it was edited from, says it was edited, and names the pack.
    func testAnEditedIndicatorKeepsItsRevision() {
        let shipped = indicator("Shipped", revision: 3)
        var edited = shipped
        edited.rule = .event("event.exec != nil")
        let hit = IndicatorHit(edited, against: Indicator.byID([shipped]), pack: 12, evaluatedBy: .securityExtension)
        XCTAssertTrue(hit.edited)
        XCTAssertEqual(hit.revision, 3)
        XCTAssertEqual(hit.pack, 12)
    }

    /// The record writes both as numbers, reads them back, and reads a hit Mac Monitor 3.1 wrote, which has
    /// neither.
    func testTheRecordsKeys() throws {
        let shipped = indicator("Shipped", revision: 3)
        let hit = IndicatorHit(shipped, against: Indicator.byID([shipped]), pack: 12, evaluatedBy: .securityExtension)
        var object = try jsonObject(encoding: hit)
        XCTAssertEqual(object["revision"] as? Int, 3)
        XCTAssertEqual(object["pack"] as? Int, 12)
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertEqual(try JSONDecoder().decode(IndicatorHit.self, from: data), hit)

        object["revision"] = nil
        object["pack"] = nil
        let earlier = try JSONDecoder().decode(IndicatorHit.self,
                                               from: try JSONSerialization.data(withJSONObject: object))
        XCTAssertNil(earlier.revision)
        XCTAssertNil(earlier.pack)
        XCTAssertEqual(earlier.id, hit.id)
    }

    /// A compiled set stamps the pack it was compiled for on the hits of the shipped indicators it runs.
    func testACompiledSetNamesThePack() throws {
        let pack = try releaseFixture(2).pack
        let mine = indicator("Mine", revision: nil)
        let compiled = CompiledIndicators(pack.indicators + [mine], defaults: Indicator.byID(pack.indicators),
                                          pack: pack.pack.sequence)
        let hits = Dictionary(compiled.ruleHits.map { ($0.id, $0) }) { first, _ in first }
        let run = pack.indicators.filter(\.isEnabled)
        XCTAssertEqual(run.count, 2)
        XCTAssertEqual(hits.count, run.count + 1)
        for shipped in run {
            XCTAssertEqual(hits[shipped.id]?.pack, 2, shipped.name)
            XCTAssertEqual(hits[shipped.id]?.revision, shipped.revision, shipped.name)
            XCTAssertNotNil(shipped.revision, shipped.name)
        }
        XCTAssertNil(hits[mine.id]?.pack)
        XCTAssertTrue(CompiledIndicators(pack.indicators, defaults: Indicator.byID(pack.indicators)).ruleHits
            .allSatisfy { $0.pack == nil })
    }

    /// The Security Extension's hits name the pack it has: none for the build's own indicators, the pack once one
    /// is installed, and still after a change to the set and a restart.
    func testTheSecurityExtensionNamesTheInstalledPack() throws {
        let directory = try makeIndicatorDirectory()
        let linked = try linkedFixtures()
        let packs = { (set: SavedIndicatorSet) in set.queue.sync { Set(set.compiled.ruleHits.map(\.pack)) } }
        let set = try makeSavedIndicatorSet(in: directory, defaults: linked, verifier: try packVerifier())
        set.load()
        XCTAssertEqual(packs(set), [nil])

        let installed = set.send(IndicatorRequest(.installPack, pack: try releaseFixture(2).file))
        XCTAssertEqual(installed.status, .ok, installed.failure ?? "")
        XCTAssertEqual(packs(set), [2])
        let first = try XCTUnwrap(installed.indicators.first), second = installed.indicators[1]
        XCTAssertEqual(set.send(IndicatorRequest(.setEnabled, ids: [second.id], enabled: false)).status, .ok)
        XCTAssertEqual(packs(set), [2])

        let restarted = try makeSavedIndicatorSet(in: directory, defaults: linked, verifier: try packVerifier())
        restarted.load()
        XCTAssertEqual(packs(restarted), [2])
        XCTAssertEqual(restarted.queue.sync { restarted.compiled.ruleHits.map(\.id) }, [first.id])
        XCTAssertEqual(restarted.queue.sync { restarted.compiled.ruleHits.first?.revision }, 2)
    }

    /// Mac Monitor's own hits, matched as it writes a record, name the pack the Security Extension last said it
    /// has, which the engine keeps for the next time Mac Monitor opens.
    func testMacMonitorNamesThePackItLastHeardOf() throws {
        let defaults = makeDefaults()
        XCTAssertEqual(IndicatorEngine.cachedPack(in: defaults), 0)
        let linked = try linkedFixtures()
        let set = try makeSavedIndicatorSet(defaults: linked, verifier: try packVerifier())
        set.load()
        let engine = IndicatorEngine(defaults: defaults, transport: transport(to: set, access: .write))
        send(IndicatorRequest(.list), through: engine)
        XCTAssertEqual(IndicatorEngine.cachedPack(in: defaults), 0)
        send(IndicatorRequest(.installPack, pack: try releaseFixture(2).file), through: engine)
        XCTAssertEqual(IndicatorEngine.cachedPack(in: defaults), 2)
    }
}
