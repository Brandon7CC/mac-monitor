//
//  SymbolStandInTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import AppKit
@testable import SutroESFramework


// MARK: - Symbol stand-ins
/// Pins the stand-in of each SF Symbol macOS 13 lacks, and that a Mac picks today's symbol wherever it has it.
final class SymbolStandInTests: XCTestCase {
    /// The symbols a macOS 13.6 VM drew nothing for, with the first macOS CoreGlyphs gives each, frozen.
    private static let missingOnMacOS13 = [
        "exclamationmark.magnifyingglass": 14, "apple.terminal": 14, "staroflife.shield": 14,
        "shield.lefthalf.filled.trianglebadge.exclamationmark": 14,
        "line.diagonal.trianglehead.up.right": 26, "line.diagonal.trianglehead.up.right.left.down": 26
    ]

    /// Every symbol macOS 13 lacks has a stand-in from the first macOS that draws it. A stand-in needs none.
    func testEverySymbolMacOS13LacksHasAStandIn() throws {
        XCTAssertEqual(Set(SymbolStandIn.table.keys), Set(Self.missingOnMacOS13.keys))
        for (name, major) in Self.missingOnMacOS13 {
            XCTAssertEqual(SymbolStandIn.table[name].map { Self.text($0.since) }, "\(major).0.0", name)
            let standIn = try XCTUnwrap(SymbolStandIn.standIn(for: name), name)
            XCTAssertNil(SymbolStandIn.standIn(for: standIn), standIn)
        }
        XCTAssertNil(SymbolStandIn.standIn(for: SymbolStandIn.unknown))
    }

    /// A macOS older than a symbol picks its stand-in, and the first macOS that draws it, or a later one, picks the
    /// symbol. A name without a stand-in is its own on every macOS.
    func testEachMacOSPicksTheSymbolsItHas() {
        for (name, major) in Self.missingOnMacOS13 {
            let older = [Self.macOS(13, 1), Self.macOS(13, 6)] + (major > 14 ? [Self.macOS(14), Self.macOS(15, 7)] : [])
            for os in older {
                XCTAssertEqual(SymbolStandIn.symbol(name, on: os), SymbolStandIn.standIn(for: name),
                               "\(name) on \(Self.text(os))")
            }
            for os in [Self.macOS(major), Self.macOS(major, 1), Self.macOS(27, 2)] {
                XCTAssertEqual(SymbolStandIn.symbol(name, on: os), name, "\(name) on \(Self.text(os))")
            }
        }
        XCTAssertEqual(SymbolStandIn.symbol("cpu", on: Self.macOS(13, 1)), "cpu")
    }

    /// This Mac picks a symbol exactly when it draws it, so macOS 14 and later keep the symbols they drew. It draws
    /// every stand-in and every event's symbol.
    func testThisMacPicksTodaysSymbolWhereItHasIt() {
        let thisMac = ProcessInfo.processInfo.operatingSystemVersion
        for (name, entry) in SymbolStandIn.table {
            XCTAssertEqual(SymbolStandIn.symbol(name, on: thisMac), Self.draws(name) ? name : entry.standIn, name)
            XCTAssertTrue(Self.draws(entry.standIn), entry.standIn)
        }
        XCTAssertTrue(Self.draws(SymbolStandIn.unknown))
        for (event, symbol) in ModeledEvent.symbols {
            XCTAssertTrue(Self.draws(symbol), "\(event): \(symbol)")
        }
    }

    /// Each stand-in is from macOS 13.0 or earlier, and each symbol it stands in for is from the macOS CoreGlyphs
    /// gives. macOS 13.1 draws every symbol the framework names: the events', the linked pack's and the built-in
    /// marks', and the one an indicator without a symbol decodes with.
    func testStandInsAgreeWithCoreGlyphs() throws {
        let firstMacOS = try Self.coreGlyphsFirstMacOS()
        let (macOS13, macOS13_1) = (Self.macOS(13), Self.macOS(13, 1))
        for (name, entry) in SymbolStandIn.table {
            XCTAssertEqual(firstMacOS[name].map(Self.text), Self.text(entry.since), name)
            let standIn = try XCTUnwrap(firstMacOS[entry.standIn], entry.standIn)
            XCTAssertTrue(macOS13.isAtLeast(standIn), entry.standIn)
        }
        XCTAssertTrue(firstMacOS[SymbolStandIn.unknown].map(macOS13.isAtLeast) ?? false)
        let decoded = try JSONDecoder().decode(Indicator.self, from: Data(#"{"name": "A", "predicate": "1=1"}"#.utf8))
        let indicators = Indicator.defaults + Indicator.builtInMarks + [decoded]
        let drawn = Set(ModeledEvent.symbols(on: macOS13_1).values)
            .union(indicators.map { SymbolStandIn.symbol($0.symbol, on: macOS13_1) })
        for name in drawn {
            let first = try XCTUnwrap(firstMacOS[name], "CoreGlyphs doesn't date \(name)")
            XCTAssertTrue(macOS13.isAtLeast(first), name)
        }
    }
}


// MARK: - Helpers
private extension SymbolStandInTests {
    /// - Parameters:
    ///   - major: A major macOS version.
    ///   - minor: Its minor version.
    /// - Returns: The version.
    static func macOS(_ major: Int, _ minor: Int = 0) -> OperatingSystemVersion {
        OperatingSystemVersion(majorVersion: major, minorVersion: minor, patchVersion: 0)
    }

    /// - Parameter version: A macOS version.
    /// - Returns: It as text, such as `14.0.0`, so a failure says which.
    static func text(_ version: OperatingSystemVersion) -> String {
        "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
    }

    /// - Parameter name: An SF Symbol's name.
    /// - Returns: Does AppKit on this Mac draw it?
    static func draws(_ name: String) -> Bool {
        NSImage(systemSymbolName: name, accessibilityDescription: nil) != nil
    }

    /// The first macOS of every SF Symbol, as this Mac's CoreGlyphs dates them.
    ///
    /// - Returns: Each symbol's first macOS, by name.
    /// - Throws: `XCTSkip` when this Mac's CoreGlyphs has no dates in the shape this reads.
    static func coreGlyphsFirstMacOS() throws -> [String: OperatingSystemVersion] {
        let url = URL(fileURLWithPath: "/System/Library/CoreServices/CoreGlyphs.bundle/Contents/Resources")
            .appendingPathComponent("name_availability.plist")
        guard let data = try? Data(contentsOf: url),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let years = plist["symbols"] as? [String: String],
              let releases = plist["year_to_release"] as? [String: [String: String]] else {
            throw XCTSkip("This Mac's CoreGlyphs doesn't date its symbols.")
        }
        return years.compactMapValues { year in
            releases[year]?["macOS"].map { text in
                let parts = text.split(separator: ".").compactMap { Int($0) }
                return macOS(parts.first ?? 0, parts.dropFirst().first ?? 0)
            }
        }
    }
}
