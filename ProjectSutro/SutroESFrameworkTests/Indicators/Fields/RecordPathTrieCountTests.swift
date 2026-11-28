//
//  RecordPathTrieCountTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Counting an array on the walk
/// Pins what an array's `.@count` costs the walk of an event's encoding (``RecordPathTrie``): the array's own count,
/// with none of its elements encoded unless its strings are read too, and no allocation beyond the walk's own.
final class RecordPathTrieCountTests: XCTestCase {
    /// An array of strings that counts how often it's encoded: how often the walk goes down into it.
    private struct Strings: RandomAccessCollection, Encodable {
        /// How often one has been encoded.
        static var encoded = 0
        let startIndex = 0
        let endIndex: Int

        /// - Parameter position: An element's place.
        /// - Returns: The element.
        subscript(position: Int) -> String { "x" }

        /// - Parameter encoder: The encoder.
        /// - Throws: What encoding an element throws.
        func encode(to encoder: Encoder) throws {
            Self.encoded += 1
            var container = encoder.unkeyedContainer()
            for element in self { try container.encode(element) }
        }
    }

    /// An array whose size alone is read is counted where the walk meets it, without going down into it. One whose
    /// strings are read too is gone down into, and counted once.
    func testAnArrayIsCountedWithoutWalkingIt() throws {
        let elements = Strings(endIndex: 1_000)
        let rules = "event.close.yara_scan.rules", count = "event.close.yara_scan.rules.@count"
        for (paths, encoded) in [([count], 0), ([count, rules], 1)] {
            let trie = RecordPathTrie(try paths.map { path throws(SensorProblem) in try IndicatorField.record(path) })
            let walk = RecordWalk(trie)
            let node = ["event", "close", "yara_scan", "rules"].reduce(Int32(0)) { trie.child(of: $0, $1) }
            Strings.encoded = 0
            try walk.descend(elements, at: node)
            XCTAssertEqual(Strings.encoded, encoded, "\(paths)")
            XCTAssertEqual(walk.arrays.values.map(\.count), encoded == 0 ? [] : [1_000], "\(paths)")
            let counts = walk.found.filter { trie.nodes[Int($0.0)].field?.path == count }
            XCTAssertEqual(counts.map(\.1), [.number(1_000, isInteger: true)], "\(paths)")
        }
    }

    /// The size of names the record works out, which a count takes without making them, is how many names there are:
    /// for each bit alone, none, every bit and random values, and for every permission a setmode adds to a file, a
    /// directory, a sticky one or a mode that isn't known.
    func testAWorkedOutArraysSizeIsItsNamesCount() {
        var generator = SeededGenerator(seed: 0x5EED_C0DE)
        let values = (0..<32).map { Int32(bitPattern: 1 << $0) } + [0, -1]
            + (0..<500).map { _ in Int32.random(in: .min ... .max, using: &generator) }
        for value in values {
            let flags = Int64(UInt32(bitPattern: value))
            XCTAssertEqual(ProcessHelpers.codeSigningFlagCount(flags), ProcessHelpers.codeSigningFlagNames(flags).count)
            for table in [MemoryMappingNames.protection, .flags] {
                XCTAssertEqual(table.nameCount(value), table.names(value).count, "\(value)")
            }
        }
        for previous in [nil, FileMode(0o100644), FileMode(0o104755), FileMode(0o040755), FileMode(0o041777)] {
            for bits in 0..<0o10000 {
                let mode = FileMode(bits)
                XCTAssertEqual(FileModeCallout.addedCount(to: mode, from: previous),
                               FileModeCallout.added(to: mode, from: previous).count, "\(bits)")
            }
        }
    }

    /// Counting allocates nothing the walk doesn't. A scan's counts read beside its rules allocate what its rules
    /// alone do. The count of names the record works out from a number allocates what that number does, as the names
    /// aren't made. An exec's descriptors count with the same allocations at 10,000 as at 1. Counted only in an
    /// optimized build, which `test-performance.sh` makes. An unoptimized one allocates for its own reasons.
    func testCountingAllocatesNothing() throws {
        try XCTSkipUnless(PerformanceRun.isEnabled && AllocationCounter.isAvailable, PerformanceRun.skipReason)
        /// - Parameters:
        ///   - paths: Key paths the walk reads.
        ///   - message: The event.
        /// - Returns: How many allocations a walk of the event that reads them makes.
        func allocations(_ paths: [String], _ message: Message) throws -> Int {
            let trie = RecordPathTrie(try paths.map { path throws(SensorProblem) in try IndicatorField.record(path) })
            trie.read(message) { _, _ in }
            return AllocationCounter.counting { trie.read(message) { _, _ in } }
        }
        let scan = "event.close.yara_scan"
        let close = try countedScanMessages()[3]
        XCTAssertEqual(try allocations(["\(scan).rules", "\(scan).rules.@count", "\(scan).report_only.@count",
                                        "\(scan).names.@count"], close),
                       try allocations(["\(scan).rules"], close))
        let corpus = try SyntheticCorpus.records().map(\.message)
        for (type, count, number) in [
            ("EXEC", "process.codesigning_flag_names.@count", "process.codesigning_flags"),
            ("EXEC", "event.exec.target.codesigning_flag_names.@count", "event.exec.target.codesigning_flags"),
            ("MMAP", "event.mmap.protection_names.@count", "event.mmap.protection"),
            ("MMAP", "event.mmap.max_protection_names.@count", "event.mmap.max_protection"),
            ("MMAP", "event.mmap.flag_names.@count", "event.mmap.flags"),
            ("SETMODE", "event.setmode.mode_added.@count", "event.setmode.mode"),
        ] {
            let message = try XCTUnwrap(corpus.first { $0.es_event_type == "ES_EVENT_TYPE_NOTIFY_\(type)" }, type)
            XCTAssertEqual(try allocations([count], message), try allocations([number], message), count)
        }
        let descriptor = try XCTUnwrap(corpusExec().event.exec?.fds.first)
        let few = try corpusExec { $0.fds = [descriptor] }
        let many = try corpusExec { $0.fds = Array(repeating: descriptor, count: 10_000) }
        XCTAssertEqual(try allocations(["event.exec.fds.@count"], many),
                       try allocations(["event.exec.fds.@count"], few))
    }
}
