//
//  SavedIndicators.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Saving
/// The indicators as user defaults keep them: only what someone changed, on top of the ``Indicator/defaults`` this
/// build ships. An update can then change, add or drop a shipped indicator for everyone who didn't edit it.
///
/// It's a JSON object. `entries` lists the indicators in order. A shipped indicator nobody edited is saved by identity
/// (`{"default": id}`), with only the switches, tactic, technique or severity someone changed, and takes everything
/// else from this build: a later build's changes to its rule, its switches or its classification reach everyone who
/// didn't change them. An edited shipped indicator, and one someone added, is saved in full, and kept as saved through
/// any update. `deleted` lists the shipped indicators someone deleted, so they don't come back.
///
/// Each entry is decoded on its own, so one that doesn't decode loses only itself. It might have a color
/// a newer build added, or be a newer build's rule over several events (a `kind` other than ``Indicator/kind``). It's
/// kept as it was saved and written back after the rest.
public struct SavedIndicators {
    /// The indicators, in order: the saved ones, then shipped indicators that are new since the last save.
    public var indicators: [Indicator]
    /// The shipped indicators they're saved against.
    private let defaults: [Indicator]
    /// The shipped indicators someone deleted, by identity.
    private var deleted: Set<UUID> = []
    /// The entries that didn't decode, as `JSONSerialization` read them.
    private var undecodable: [Any] = []

    /// How many entries didn't decode.
    public var undecodableCount: Int { undecodable.count }

    /// - Parameters:
    ///   - indicators: The indicators, with no undecodable entries.
    ///   - defaults: The shipped indicators.
    public init(_ indicators: [Indicator], defaults: [Indicator] = Indicator.defaults) {
        self.indicators = indicators
        self.defaults = defaults
    }

    /// Decode saved indicators one entry at a time, and apply them to the shipped ones.
    ///
    /// - Parameters:
    ///   - data: The saved JSON.
    ///   - defaults: The shipped indicators.
    /// - Returns: `nil` when the data isn't an object with `entries`.
    public init?(data: Data, defaults: [Indicator] = Indicator.defaults) {
        self.init(object: try? JSONSerialization.jsonObject(with: data), defaults: defaults)
    }

    /// Decode saved indicators already read as JSON, such as the `saved` object of the Security Extension's indicator
    /// file (``IndicatorFile``), as ``init(data:defaults:)`` does.
    ///
    /// - Parameters:
    ///   - object: The saved JSON, as `JSONSerialization` read it.
    ///   - defaults: The shipped indicators.
    /// - Returns: `nil` when it isn't an object with `entries`.
    public init?(object: Any?, defaults: [Indicator] = Indicator.defaults) {
        guard let saved = object as? [String: Any], let entries = saved["entries"] as? [Any] else { return nil }
        deleted = Set((saved["deleted"] as? [String] ?? []).compactMap(UUID.init(uuidString:)))
        self.defaults = defaults
        indicators = []
        let shipped = Dictionary(uniqueKeysWithValues: defaults.map { ($0.id, $0) })
        for entry in entries {
            if let reference = entry as? [String: Any], let id = reference["default"] {
                guard let id = (id as? String).flatMap(UUID.init(uuidString:)),
                      Self.isEventKind(reference["kind"]) else {
                    undecodable.append(entry)
                    continue
                }
                // A shipped indicator this build no longer ships goes.
                guard var indicator = shipped[id] else { continue }
                indicator.applySwitches(from: reference)
                indicator.applyClassification(from: reference)
                indicators.append(indicator)
            } else if let entryData = try? JSONSerialization.data(withJSONObject: entry, options: .fragmentsAllowed),
                      let saved = try? JSONDecoder().decode(Indicator.self, from: entryData) {
                guard var indicator = shipped[saved.id], indicator.hasSameRule(as: saved) else {
                    /// An edited shipped indicator saved without a severity, as Mac Monitor 3.0 saved one, keeps the
                    /// shipped one's.
                    var edited = saved
                    if (entry as? [String: Any])?["severity"] == nil, let original = shipped[saved.id] {
                        edited.severity = original.severity
                    }
                    indicators.append(edited)
                    continue
                }
                // Saved in full with the rule this build ships: this build's version, with its switches.
                indicator.copySwitches(from: saved)
                indicator.applyClassification(from: entry as? [String: Any] ?? [:])
                indicators.append(indicator)
            } else {
                undecodable.append(entry)
            }
        }
        let listed = Set(indicators.map(\.id))
        indicators += defaults.filter { !listed.contains($0.id) && !deleted.contains($0.id) }
    }

    /// Does a saved reference name a rule on one event? As ``Indicator/init(from:)`` reads a full entry's `kind`:
    /// missing or `null` is one, and so is ``Indicator/kind``; anything else, a string or not, is a rule this build
    /// can't run.
    ///
    /// - Parameter kind: The reference's `kind` value, or `nil` when it has none.
    /// - Returns: `true` when it's a rule on one event.
    static func isEventKind(_ kind: Any?) -> Bool {
        kind == nil || kind is NSNull || (kind as? String) == Indicator.kind
    }

    /// The indicators, then the entries that didn't decode, as the JSON object ``init(data:defaults:)`` reads.
    ///
    /// - Returns: The data to save, or `nil` if it can't be encoded.
    public func encoded() -> Data? {
        encodedObject().flatMap { try? JSONSerialization.data(withJSONObject: $0) }
    }

    /// The indicators, then the entries that didn't decode, as the JSON object ``init(object:defaults:)`` reads, for a
    /// file that holds it, such as ``IndicatorFile``.
    ///
    /// - Returns: The object, or `nil` if an indicator can't be encoded.
    public func encodedObject() -> [String: Any]? {
        let shipped = Dictionary(uniqueKeysWithValues: defaults.map { ($0.id, $0) })
        var entries: [Any] = []
        for indicator in indicators {
            if let original = shipped[indicator.id], original.hasSameRule(as: indicator) {
                /// Only what someone changed, so a later build's own reach those who didn't.
                var reference: [String: Any] = ["default": indicator.id.uuidString]
                if indicator.isEnabled != original.isEnabled { reference["isEnabled"] = indicator.isEnabled }
                if indicator.tableMarks != original.tableMarks { reference["tableMarks"] = indicator.tableMarks.names }
                if indicator.tactic != original.tactic { reference["tactic"] = indicator.tactic?.rawValue ?? NSNull() }
                if indicator.technique != original.technique {
                    reference["technique"] = indicator.technique ?? NSNull()
                }
                if indicator.severity != original.severity { reference["severity"] = indicator.severity.rawValue }
                entries.append(reference)
            } else {
                guard let data = try? JSONEncoder().encode(indicator),
                      let object = try? JSONSerialization.jsonObject(with: data) else { return nil }
                entries.append(object)
            }
        }
        let present = Set(indicators.map(\.id))
        let deleted = deleted.union(defaults.map(\.id)).subtracting(present)
        return ["entries": entries + undecodable, "deleted": deleted.map(\.uuidString).sorted()]
    }
}

