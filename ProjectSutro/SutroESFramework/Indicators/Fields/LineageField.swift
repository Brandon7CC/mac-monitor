//
//  LineageField.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation


// MARK: - Lineage fields
/// The fields an indicator reads of the ancestors of an event's process: its parent, its grandparent, the first
/// below launchd, and every ancestor at once. They follow the direct fields a record has (``IndicatorField``), and
/// unlike those they aren't in the record: the Security Extension reads them from its lineage table
/// (``ProcessLineage``), by the event's process.
///
/// An ancestor's fields are named as a process's are:
///
///     lineage.parent.executable.path ENDSWITH "/osascript"
///     lineage.origin.signing_id == "com.microsoft.Word"
///     ANY lineage.command_lines CONTAINS "base64"
///
/// The same fields under `launched_by` follow the launched-by parents (``ProcessLineage/Chain/launchedBy``): what
/// the process tree shows, where an XPC service's parent is its host app and not launchd.
///
///     launched_by.parent.signing_id == "com.apple.Safari"
///
/// A field of an ancestor the process doesn't have is `nil`, as every one is when lineage isn't tracked.
enum LineageField {
    /// A chain of ancestors, by what its key paths start with.
    typealias Chain = ProcessLineage.Chain

    /// One ancestor of the chain.
    enum Slot: String, CaseIterable {
        /// The process that forked the event's process.
        case parent
        /// The parent's parent.
        case grandparent
        /// The first ancestor below launchd.
        case origin
    }

    /// What's read of an ancestor.
    enum Attribute: Int, CaseIterable {
        case path, commandLine, signingID, teamID, codesigningType

        /// Its key under an ancestor, as a process's record has it.
        var key: String {
            ["executable.path", "command_line", "signing_id", "team_id", "codesigning_type"][rawValue]
        }

        /// Its key for every ancestor's at once.
        var list: String {
            ["paths", "command_lines", "signing_ids", "team_ids", "codesigning_types"][rawValue]
        }

        /// Its name in a field's description.
        var name: String {
            ["ExecutablePath", "CommandLine", "SigningID", "TeamID", "CodesigningType"][rawValue]
        }

        /// - Parameter program: An ancestor.
        /// - Returns: Its value, or `nil` when it isn't known.
        func value(of program: ProcessProgram) -> String? {
            switch self {
            case .path: program.path
            case .commandLine: program.commandLine
            case .signingID: program.signingID
            case .teamID: program.teamID
            case .codesigningType: program.codesigningType
            }
        }
    }

    /// How many fields a chain has: each slot's attributes, then each attribute's list.
    static let perChain = (Slot.allCases.count + 1) * Attribute.allCases.count

    /// Every lineage field's key path, kind and name, in the order their numbers follow the record's direct fields:
    /// for each chain, each slot's attributes, then the lists.
    static let all: [(path: String, kind: IndicatorField.Kind, name: String)] = Chain.allCases.flatMap { chain in
        Slot.allCases.flatMap { slot in
            Attribute.allCases.map { attribute in
                ("\(chain.rawValue).\(slot.rawValue).\(attribute.key)", IndicatorField.Kind.string,
                 "\(chain)\(slot.rawValue.capitalized)\(attribute.name)")
            }
        } + Attribute.allCases.map { attribute in
            ("\(chain.rawValue).\(attribute.list)", IndicatorField.Kind.strings, "\(chain)\(attribute.name)s")
        }
    }

    /// Every lineage field's key path, as its keys.
    private static let keys = all.map { $0.path.split(separator: ".").map(String.init) }

    /// How many of a key path's leading keys start a lineage field's key path.
    ///
    /// - Parameter path: A key path's keys.
    /// - Returns: The number that do: `path.count` for a lineage field or the start of one, and 0 for a key path
    ///   that isn't an ancestor's.
    static func validCount(of path: [String]) -> Int {
        (1...max(path.count, 1)).last { count in keys.contains { $0.starts(with: path.prefix(count)) } } ?? 0
    }

    /// The keys right under a key path, among the lineage fields' key paths, in their order.
    ///
    /// - Parameter parent: A key path's keys, or none for the chains themselves.
    /// - Returns: The next keys: `parent`, `grandparent`, `origin` and the lists under `lineage`. None under a
    ///   field, or under a key path that isn't the start of one.
    static func children(of parent: [String]) -> [String] {
        var children: [String] = []
        for path in keys where path.count > parent.count && path.starts(with: parent)
            && !children.contains(path[parent.count]) {
            children.append(path[parent.count])
        }
        return children
    }

    /// What the predicate editor's completions say of a lineage key path.
    ///
    /// - Parameter path: A key path's keys.
    /// - Returns: Its JSON type and a line about it, or `nil` for a key path that isn't a lineage field or the
    ///   start of one.
    static func completion(of path: [String]) -> (type: String, summary: String)? {
        guard let chain = path.first.flatMap(Chain.init(rawValue:)), validCount(of: path) == path.count else {
            return nil
        }
        let whose = chain == .lineage ? "forked" : "caused"
        guard path.count > 1 else {
            return ("object", chain == .lineage
                    ? "The processes that forked the event's process: its parent, and every ancestor further up."
                    : "The processes that caused the event's process to run, as the process tree's launched-by "
                        + "parents.")
        }
        let field = all.first { $0.path == path.joined(separator: ".") }
        if let slot = Slot(rawValue: path[1]) {
            let who = ["the process that \(whose) the event's process", "that process's own parent",
                       "the first ancestor below launchd"][Slot.allCases.firstIndex(of: slot) ?? 0]
            if path.count == 2 { return ("object", who.prefix(1).uppercased() + who.dropFirst() + ".") }
            return (field == nil ? "object" : "string", "Of \(who).")
        }
        return ("array", "Every ancestor's, nearest first, for ANY.")
    }

    /// - Parameter offset: A field's place among the lineage fields (``all``).
    /// - Returns: The chain it reads.
    static func chain(at offset: Int) -> Chain {
        Chain.allCases[offset / perChain]
    }

    /// A lineage field's value.
    ///
    /// - Parameters:
    ///   - offset: The field's place among the lineage fields (``all``).
    ///   - ancestors: The ancestors of the event's process along the field's chain, nearest first.
    /// - Returns: The value: an ancestor's, `nil` for one the process doesn't have, or every ancestor's that's
    ///   known.
    static func value(at offset: Int, of ancestors: [ProcessProgram]) -> IndicatorValue {
        let attribute = Attribute.allCases[offset % Attribute.allCases.count]
        switch (offset % perChain) / Attribute.allCases.count {
        case 0: return IndicatorValue(ancestors.first.flatMap(attribute.value))
        case 1: return IndicatorValue(ancestors.count > 1 ? attribute.value(of: ancestors[1]) : nil)
        case 2: return IndicatorValue(ancestors.last.flatMap(attribute.value))
        default: return .strings(ancestors.compactMap(attribute.value))
        }
    }
}
