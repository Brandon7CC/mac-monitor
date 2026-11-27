//
//  SymbolStandIn+Drawing.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/25/26.
//

import AppKit
import SutroESFramework


// MARK: - Symbols from data
extension SymbolStandIn {
    /// The symbol drawn for each name looked up so far.
    private static let drawnNames = NSCache<NSString, NSString>()

    /// The symbol this Mac draws for a name that comes from data, such as an indicator's from a pack, the user or a
    /// verdict.
    ///
    /// - Parameter name: An SF Symbol's name.
    /// - Returns: The name when this Mac has the symbol, else its stand-in, else ``SymbolStandIn/unknown``.
    static func drawn(for name: String) -> String {
        if let drawn = drawnNames.object(forKey: name as NSString) { return drawn as String }
        let drawn = [name, standIn(for: name)].compactMap { $0 }.first(where: exists) ?? unknown
        drawnNames.setObject(drawn as NSString, forKey: name as NSString)
        return drawn
    }

    /// - Parameter name: A symbol's name.
    /// - Returns: Is there an SF Symbol by that name on this Mac?
    static func exists(_ name: String) -> Bool {
        !name.isEmpty && NSImage(systemSymbolName: name, accessibilityDescription: nil) != nil
    }
}
