//
//  IndicatorPackTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Indicator packs
/// Pins how an indicator pack's payload reads: its header, its indicators, a later Mac Monitor's entries kept as
/// needing it, and each way a payload is refused. Also that a pack imports as a file of indicators.
final class IndicatorPackTests: XCTestCase {
    /// The core identity the packs here list.
    private static let core = "6D4D0F1D-0000-4000-8000-000000000009"

    /// A pack's payload as JSON.
    ///
    /// - Parameters:
    ///   - entries: Its indicators, as JSON objects.
    ///   - header: Header keys to change.
    ///   - top: Top-level keys to change.
    /// - Returns: The payload's bytes.
    private func payload(_ entries: [[String: Any]], header: [String: Any] = [:], top: [String: Any] = [:]) throws
        -> Data {
        let pack: [String: Any] = ["sequence": 1, "published": "2026-11-15T09:35:16Z",
                                   "commit": String(repeating: "a", count: 40), "min_engine": "3.2.0",
                                   "core": [Self.core], "retired": ["6D4D0F1D-0000-4000-8000-00000000000C"]]
        let file: [String: Any] = ["format": IndicatorExchange.format, "version": 2,
                                   "pack": pack.merging(header) { $1 }, "indicators": entries]
        return try JSONSerialization.data(withJSONObject: file.merging(top) { $1 })
    }

    /// An indicator entry as a pack ships one.
    ///
    /// - Parameters:
    ///   - id: Its identity.
    ///   - minEngine: The oldest Mac Monitor that can run it.
    ///   - kind: Its kind, or `nil` for a rule on one event.
    /// - Returns: The entry.
    private func entry(_ id: String = core, minEngine: String = "3.2.0", kind: String? = nil) -> [String: Any] {
        var entry: [String: Any] = ["id": id, "revision": 2, "minEngine": minEngine, "name": "Entry \(id.suffix(4))",
                                    "description": "", "severity": "low", "isEnabled": true, "symbol": "star",
                                    "color": "red", "tableMarks": ["dot"], "tactic": "stealth",
                                    "predicate": "event.exec != nil"]
        entry["kind"] = kind
        return entry
    }

    /// A pack reads with its header and indicators, a sequence's included.
    func testPackReads() throws {
        let sequence = try XCTUnwrap(try JSONSerialization.jsonObject(
            with: Data(IndicatorSequenceTests.packEntry.utf8)) as? [String: Any])
        let pack = try IndicatorPack.decode(try payload([entry(), sequence]))
        XCTAssertEqual(pack.pack.sequence, 1)
        XCTAssertEqual(pack.pack.minEngine, ReleaseVersion(3, 2, 0))
        XCTAssertEqual(pack.pack.core, [UUID(uuidString: Self.core)])
        XCTAssertEqual(pack.indicators.count, 2)
        XCTAssertEqual(pack.indicators[0].tactic, .stealth)
        XCTAssertEqual(pack.indicators[0].revision, 2)
        XCTAssertEqual(pack.indicators[1].rule.kind, .sequence)
        XCTAssertEqual(pack.newer, [])
    }

    /// An entry a later Mac Monitor wrote, of a kind this build doesn't know, is kept as needing it. One that reads
    /// but needs a later Mac Monitor is an indicator that isn't run. One that doesn't read and doesn't need a later
    /// Mac Monitor fails the pack.
    func testLaterEntries() throws {
        let laterID = "6D4D0F1D-0000-4000-8000-0000000000F1", readableID = "6D4D0F1D-0000-4000-8000-0000000000F2"
        let pack = try IndicatorPack.decode(try payload([
            entry(), entry(laterID, minEngine: "9.0.0", kind: "chain"), entry(readableID, minEngine: "9.0.0"),
        ]))
        XCTAssertEqual(pack.newer.map(\.id), [UUID(uuidString: laterID)])
        XCTAssertEqual(pack.newer.first?.minEngine, ReleaseVersion(9, 0, 0))
        XCTAssertEqual(pack.indicators.map(\.id.uuidString), [Self.core, readableID])
        XCTAssertFalse(pack.indicators[1].isSupported)
        XCTAssertThrowsError(try IndicatorPack.decode(try payload([entry(), entry(laterID, kind: "chain")])))
    }

    /// Each way a payload is refused says why.
    func testRefusals() throws {
        let other = "6D4D0F1D-0000-4000-8000-0000000000F3"
        let cases: [(Data, String)] = [
            (Data("[]".utf8), "isn't a JSON object"),
            (try payload([entry()], top: ["format": "something.else"]), "isn't Mac Monitor indicators"),
            (try payload([entry()], top: ["version": 1]), "not a pack"),
            (try payload([entry()], top: ["version": IndicatorExchange.version + 1]), "newer than this Mac Monitor"),
            (try payload([entry()], header: ["min_engine": "9.0.0"]), "needs Mac Monitor 9.0.0"),
            (try payload([entry()], header: ["min_engine": "3.2"]), "min_engine"),
            (try payload([]), "has no indicators"),
            (try payload([entry(), entry()]), "share the identity"),
            (try payload([entry(other)]), "core indicator \(Self.core)"),
            (try payload([entry(), entry("6D4D0F1D-0000-4000-8000-00000000000C")]), "retired indicator"),
            (try payload([entry().merging(["predicate": 3]) { $1 }]), "indicators[0].predicate"),
        ]
        for (data, words) in cases {
            XCTAssertThrowsError(try IndicatorPack.decode(data), words) { error in
                let reason = (error as? IndicatorPack.Problem)?.description ?? "\(error)"
                XCTAssertTrue(reason.contains(words), "\(reason) should say \(words)")
            }
        }
    }

    /// A pack's payload imports as a file of indicators, its header ignored. An export is version 1, which Mac Monitor
    /// 3.1 reads, unless it has a sequence or an indicator that names a minimum Mac Monitor.
    func testExchangeVersions() throws {
        let imported = try IndicatorExchange.indicators(from: try payload([entry()]))
        XCTAssertEqual(imported.map(\.id.uuidString), [Self.core])
        let own = Indicator(name: "Mine", description: "", symbol: "star", color: .red, predicate: "event.exec != nil")
        XCTAssertEqual(IndicatorExchange.version(of: [own]), 1)
        XCTAssertEqual(IndicatorExchange.version(of: [own] + imported), 2)
        let sequence = try JSONDecoder().decode(Indicator.self, from: Data(IndicatorSequenceTests.packEntry.utf8))
        var unversioned = sequence
        unversioned.minEngine = nil
        XCTAssertEqual(IndicatorExchange.version(of: [unversioned]), 2)
        let written = try JSONSerialization.jsonObject(with: IndicatorExchange.data(of: [own])) as? [String: Any]
        XCTAssertEqual(written?["version"] as? Int, 1)
    }

    /// A tactic ATT&CK retired reads as the one that replaced it, in a saved or shared indicator, and is never
    /// written.
    func testRetiredTacticReadsAsItsReplacement() throws {
        let json = #"{"name": "Old", "predicate": "event.exec != nil", "tactic": "defenseEvasion"}"#
        let indicator = try JSONDecoder().decode(Indicator.self, from: Data(json.utf8))
        XCTAssertEqual(indicator.tactic, .stealth)
        XCTAssertEqual(indicator.tactic?.identifier, "TA0005")
        let written = try JSONSerialization.jsonObject(with: JSONEncoder().encode(indicator)) as? [String: Any]
        XCTAssertEqual(written?["tactic"] as? String, "stealth")
        XCTAssertEqual(Indicator.Tactic.defenseImpairment.identifier, "TA0112")
        XCTAssertFalse(Indicator.Tactic.allCases.map(\.name).contains("Defense Evasion"))
    }
}
