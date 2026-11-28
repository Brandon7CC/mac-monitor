//
//  EventFact.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - A fact to show
/// One fact Event Facts shows, laid out here where it can be tested: its name, and its values side by side, as Remote
/// host shows a hostname beside its address.
public struct EventFact: Equatable, Identifiable {
    /// The fact's name, without a colon.
    public let name: String
    /// Its values: the first beside the name, the rest after it. Never empty.
    public let values: [String]
    /// What hovering over it says, if anything.
    public var help: String?
    /// Is it a long value, shown below its name in a box as wide as the facts?
    public var isLong = false

    public var id: String { name }
}
