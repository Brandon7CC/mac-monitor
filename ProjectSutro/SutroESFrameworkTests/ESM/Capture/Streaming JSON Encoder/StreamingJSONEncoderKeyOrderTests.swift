//
//  StreamingJSONEncoderKeyOrderTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - Key order
/// Pins the order macOS 13's `JSONEncoder` sorts keys in (``StreamingJSONEncoder/KeyOrder/localized``), which these
/// tests can't ask that `JSONEncoder` for: XCTest doesn't run there. The order is the one macOS 13.6 wrote
/// (``recorded``), and a record written in it is the same record, member for member, as the one written in this Mac's.
final class StreamingJSONEncoderKeyOrderTests: XCTestCase {
    private typealias KeyRanks = StreamingJSONEncoder.KeyRanks

    /// Keys in the order macOS 13.6's `JSONEncoder` wrote them with `.sortedKeys`: punctuation, digits by value,
    /// letters without regard to case.
    private static let recorded = [
        "_a", "!", "@x", "#x", "~", "1", "2", "02", "10", "a", "A", "a b", "a_", "a__b", "a_1", "a_b", "a_B", "A_b",
        "a-b", "a.b", "a0", "a00", "a1", "a01", "a1_b", "a1b", "a2", "a10", "aa", "ab", "aB", "arm64", "arm64e",
        "audit_token", "audit_token_string", "cd_hash", "cdhash", "e", "es_event_type", "event", "global_seq_num",
        "is_es_client", "is_platform_binary", "mach_time", "md5", "p1", "p2", "p02", "p10", "pid", "pid_version",
        "pidversion", "ppid", "process", "seq_num", "sha1", "sha2", "sha256", "ss", "thread", "time", "uid", "Uid",
        "UID", "version", "x y", "x_y", "x-y", "x:y", "x.y", "x86_64", "xy", "z", "Z9",
    ]

    /// An encoder that sorts as macOS 13 does, with the export's options.
    private func localized() -> StreamingJSONEncoder {
        StreamingJSONEncoder(sortsKeys: true, escapesSlashes: false, keyOrder: .localized)
    }

    /// - Parameter keys: Keys.
    /// - Returns: An object's members with those keys.
    private func members(_ keys: [String]) -> ArraySlice<StreamingJSONEncoder.Member> {
        keys.map { StreamingJSONEncoder.Member(key: $0, start: 0) }[...]
    }

    /// - Parameter object: An object of numbers.
    /// - Returns: Its JSON with its members in macOS 13's order.
    private func written(_ object: [String: Int]) -> String {
        "{" + object.keys.sorted(by: KeyRanks.precedes).map { "\"\($0)\":\(object[$0] ?? 0)" }
            .joined(separator: ",") + "}"
    }

    /// This Mac's `JSONEncoder` sorts keys in an order the encoder knows, so exports take the quick encoder.
    func testThisMacsKeyOrderIsKnown() {
        XCTAssertNotNil(StreamingJSONEncoder.jsonEncoderKeyOrder)
        XCTAssertTrue(StreamingJSONEncoder.sortsKeysAsJSONEncoderDoes)
    }

    /// Comparing keys puts them in the order macOS 13 wrote them.
    func testComparingKeysGivesTheRecordedOrder() {
        XCTAssertEqual(Self.recorded.reversed().sorted(by: KeyRanks.precedes), Self.recorded)
    }

    /// Ranks put keys in the same order as comparing them, however the keys arrive: a few at a time, some already
    /// seen, and equal keys rank equal.
    func testRanksAgreeWithComparing() throws {
        var ranks = KeyRanks()
        let arriving = Array(Self.recorded.reversed())
        for start in stride(from: 0, to: arriving.count, by: 5) {
            let keys = Array(arriving[max(0, start - 2)..<min(arriving.count, start + 5)])
            let ranked = try XCTUnwrap(ranks.ranks(of: members(keys)))
            let byRank = zip(keys, ranked).sorted { $0.1 < $1.1 }.map(\.0)
            XCTAssertEqual(byRank, keys.sorted(by: KeyRanks.precedes))
        }
        let all = try XCTUnwrap(ranks.ranks(of: members(Self.recorded)))
        XCTAssertEqual(all, Array(0..<Self.recorded.count))
        XCTAssertEqual(ranks.ranks(of: members(["pid", "uid", "pid"])).map { [$0[0] == $0[2], $0[0] < $0[1]] },
                       [true, true])
    }

    /// Past their limit the ranks take no more keys, keep ranking those they have, and an object with a new key is
    /// sorted by comparing its keys.
    func testRanksStopAtTheirLimit() throws {
        var ranks = KeyRanks()
        let many = (0..<KeyRanks.limit).map { "k\($0)" }
        XCTAssertNotNil(ranks.ranks(of: members(many)))
        XCTAssertNil(ranks.ranks(of: members(["k1", "one_more"])))
        XCTAssertEqual(ranks.ranks(of: members(["k10", "k9"])).map { $0[1] < $0[0] }, true)

        let encoder = localized()
        let full = Dictionary(uniqueKeysWithValues: many.enumerated().map { ($1, $0) })
        XCTAssertEqual(String(decoding: try encoder.encode(full), as: UTF8.self), written(full))
        let more = ["Z9": 1, "z": 2, "_a": 3, "a10": 4, "a2": 5]
        XCTAssertEqual(String(decoding: try encoder.encode(more), as: UTF8.self), written(more))
    }

    /// Objects, flat and nested, are written with their members in macOS 13's order.
    func testObjectsAreWrittenInTheRecordedOrder() throws {
        let inner = Dictionary(uniqueKeysWithValues: Self.recorded.enumerated().map { ($1, $0) })
        let json = try localized().encode(["B": inner, "a": ["Z9": 1, "z": 2, "_a": 3], "_c": [:]])
        let expected = "{\"_c\":{},\"a\":{\"_a\":3,\"z\":2,\"Z9\":1},\"B\":" + written(inner) + "}"
        XCTAssertEqual(String(decoding: json, as: UTF8.self), expected)
        XCTAssertEqual(try JSONCanonicalForm.keys(try localized().encode(inner)), Self.recorded)
    }

    /// Every synthetic record and every fixture's events, as the export's rows: written in macOS 13's order, a record
    /// is byte for byte the one written in byte order with each object's members put in that order, and none is left
    /// to `JSONEncoder`, which is what makes the export quick there.
    func testRecordsAreTheSameRecordInTheRecordedOrder() throws {
        let model = try XCTUnwrap(ExportEncoder.model)
        let context = NSManagedObjectContext(concurrencyType: .privateQueueConcurrencyType)
        context.persistentStoreCoordinator = NSPersistentStoreCoordinator(managedObjectModel: model)
        let localized = localized()
        let bytes = StreamingJSONEncoder(sortsKeys: true, escapesSlashes: false, keyOrder: .bytes)
        let events = try SyntheticCorpus.records().map { ($0.label, $0.message) }
            + allFixtureMessages().enumerated().map { ("fixture[\($0)]", $1) }
        var different: [String] = [], leftToJSONEncoder: [String] = []
        for (label, message) in events {
            let (inBytes, inLocalized, isLeft) = try context.performAndWait {
                let row = ESMessage(from: message, insertIntoManagedObjectContext: context)
                let inLocalized = try localized.encode(row)
                return (try bytes.encode(row), inLocalized, localized.state.pointee.isUnstreamable)
            }
            let expected = try JSONCanonicalForm.canonical(inBytes, by: KeyRanks.precedes)
            if String(decoding: inLocalized, as: UTF8.self) != expected { different.append(label) }
            if isLeft { leftToJSONEncoder.append(label) }
        }
        XCTAssertGreaterThan(events.count, TelemetrySchemaSource.events.count * 2)
        XCTAssertEqual(different, [], "Not the same record in macOS 13's order")
        XCTAssertEqual(leftToJSONEncoder, [], "Left to JSONEncoder")
    }

    /// macOS 13's `JSONEncoder` writes a floating-point number with other digits, so a value with one is left to
    /// `JSONEncoder` whole: here that shows as this Mac's order, `B` before `a`.
    func testAFloatingPointNumberIsLeftToJSONEncoder() throws {
        let reference = JSONEncoder()
        reference.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let encoder = localized()
        let value = ["B": 0.5, "a": 1.5]
        XCTAssertEqual(try encoder.encode(value), try reference.encode(value))
        XCTAssertTrue(encoder.state.pointee.isUnstreamable)
        XCTAssertEqual(String(decoding: try encoder.encode(["B": 1, "a": 2]), as: UTF8.self), "{\"a\":2,\"B\":1}")
    }
}
