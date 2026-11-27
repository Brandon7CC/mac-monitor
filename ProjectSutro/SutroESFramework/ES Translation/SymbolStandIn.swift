//
//  SymbolStandIn.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Stand-ins
/// The SF Symbols Mac Monitor names that macOS 13 lacks, each with the symbol drawn in its place on a macOS without
/// it. Every stand-in draws on macOS 13.
public enum SymbolStandIn {
    /// Each name macOS 13 lacks, with the first macOS that draws it and its stand-in before then. The first macOS is
    /// the one CoreGlyphs' `name_availability.plist` gives.
    static let table: [String: (since: OperatingSystemVersion, standIn: String)] = [
        "apple.terminal": (sonoma, "terminal"),
        "exclamationmark.magnifyingglass": (sonoma, "sparkle.magnifyingglass"),
        "staroflife.shield": (sonoma, "shield.lefthalf.filled"),
        "shield.lefthalf.filled.trianglebadge.exclamationmark": (sonoma, "shield.slash.fill"),
        "line.diagonal.trianglehead.up.right": (tahoe, "line.diagonal.arrow"),
        "line.diagonal.trianglehead.up.right.left.down": (tahoe, "arrow.left.arrow.right")
    ]

    /// The symbol drawn for a name this Mac lacks that has no stand-in. Every macOS Mac Monitor runs on draws it.
    public static let unknown = "questionmark.square.dashed"

    /// A symbol Mac Monitor chooses, as a macOS draws it.
    ///
    /// - Parameters:
    ///   - name: The symbol's name.
    ///   - os: The macOS that draws it.
    /// - Returns: The name, or its stand-in on a macOS older than the first to draw it.
    static func symbol(_ name: String, on os: OperatingSystemVersion) -> String {
        guard let entry = table[name], !os.isAtLeast(entry.since) else { return name }
        return entry.standIn
    }

    /// - Parameter name: A symbol's name.
    /// - Returns: The symbol drawn in its place on a macOS that lacks it, or `nil` for a name without a stand-in.
    public static func standIn(for name: String) -> String? {
        table[name]?.standIn
    }
}
