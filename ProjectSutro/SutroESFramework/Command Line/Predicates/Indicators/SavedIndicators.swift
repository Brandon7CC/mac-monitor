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
/// A switch, tactic, technique or severity someone chose for a shipped indicator stays theirs: once a reference has
/// its key, the key is kept even when the shipped value comes to agree with it, so a later build or pack that changes
/// the shipped value again doesn't change their choice. Restore Defaults forgets the choices (``forgetChoices()``).
///
/// A reference to a shipped indicator this build or the installed pack doesn't have is kept as it was saved, without
/// being listed, so its choices are there again if a later pack brings the indicator back. One to a retired
/// identity, which is never used again, is dropped.
///
/// Each entry is decoded on its own, so one that doesn't decode loses only itself. It might have a color
/// a newer build added, or be a newer build's kind of rule (a `kind` that isn't an ``Indicator/Rule/Kind``). It's
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
    /// The keys of each shipped indicator's saved reference that someone chose a value for, by identity: among
    /// ``choiceKeys``. They're written back whatever the shipped value is.
    private var chosen: [UUID: Set<String>] = [:]
    /// References to shipped indicators the shipped set doesn't have now, as they were saved.
    private var unshipped: [(id: UUID, entry: Any)] = []

    /// The keys of a saved reference that hold a choice someone made.
    static let choiceKeys: Set<String> = ["isEnabled", "tableMarks", "tactic", "technique", "severity"]

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
    ///   - retired: The identities never used again, a reference to which is dropped.
    /// - Returns: `nil` when the data isn't an object with `entries`.
    public init?(data: Data, defaults: [Indicator] = Indicator.defaults,
                 retired: Set<UUID> = Indicator.retiredDefaults) {
        self.init(object: try? JSONSerialization.jsonObject(with: data), defaults: defaults, retired: retired)
    }

    /// Decode saved indicators already read as JSON, such as the `saved` object of the Security Extension's indicator
    /// file (``IndicatorFile``), as ``init(data:defaults:)`` does.
    ///
    /// - Parameters:
    ///   - object: The saved JSON, as `JSONSerialization` read it.
    ///   - defaults: The shipped indicators.
    ///   - retired: The identities never used again, a reference to which is dropped.
    /// - Returns: `nil` when it isn't an object with `entries`.
    public init?(object: Any?, defaults: [Indicator] = Indicator.defaults,
                 retired: Set<UUID> = Indicator.retiredDefaults) {
        guard let saved = object as? [String: Any], let entries = saved["entries"] as? [Any] else { return nil }
        deleted = Set((saved["deleted"] as? [String] ?? []).compactMap(UUID.init(uuidString:)))
        self.defaults = defaults
        indicators = []
        let shipped = Dictionary(uniqueKeysWithValues: defaults.map { ($0.id, $0) })
        for entry in entries {
            if let reference = entry as? [String: Any], let id = reference["default"] {
                guard let id = (id as? String).flatMap(UUID.init(uuidString:)),
                      Self.isKnownKind(reference["kind"]) else {
                    undecodable.append(entry)
                    continue
                }
                // A shipped indicator the shipped set doesn't have now isn't listed. Its reference is kept, unless
                // its identity is retired.
                guard var indicator = shipped[id] else {
                    if !retired.contains(id) { unshipped.append((id, entry)) }
                    continue
                }
                chosen[id] = Self.choiceKeys.intersection(reference.keys)
                    .union(reference["tableMark"] != nil || reference["showsInTables"] != nil ? ["tableMarks"] : [])
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

    /// Does a saved reference name a kind of rule this build knows? As ``Indicator/init(from:)`` reads a full entry's
    /// `kind`: missing or `null` is a rule on one event, and so is any ``Indicator/Rule/Kind``. Anything else, a string
    /// or not, is a rule this build can't run.
    ///
    /// - Parameter kind: The reference's `kind` value, or `nil` when it has none.
    /// - Returns: `true` when it's a kind this build knows.
    static func isKnownKind(_ kind: Any?) -> Bool {
        kind == nil || kind is NSNull || (kind as? String).flatMap(Indicator.Rule.Kind.init(rawValue:)) != nil
    }

    /// Forget which values someone chose for the shipped indicators, and the references to ones the shipped set
    /// doesn't have: what Restore Defaults does, so each shipped indicator follows the shipped set again.
    public mutating func forgetChoices() {
        chosen = [:]
        unshipped = []
    }

    /// Did someone choose a value for a shipped indicator, or is a reference kept for one the shipped set doesn't
    /// have? Then Restore Defaults has something to forget even when the indicators are the shipped ones.
    public var hasChoices: Bool {
        !unshipped.isEmpty || chosen.values.contains { !$0.isEmpty }
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
                /// Only what someone changed or chose, so a later build's own reach those who didn't.
                let kept = chosen[indicator.id] ?? []
                var reference: [String: Any] = ["default": indicator.id.uuidString]
                if indicator.isEnabled != original.isEnabled || kept.contains("isEnabled") {
                    reference["isEnabled"] = indicator.isEnabled
                }
                if indicator.tableMarks != original.tableMarks || kept.contains("tableMarks") {
                    reference["tableMarks"] = indicator.tableMarks.names
                }
                if indicator.tactic != original.tactic || kept.contains("tactic") {
                    reference["tactic"] = indicator.tactic?.rawValue ?? NSNull()
                }
                if indicator.technique != original.technique || kept.contains("technique") {
                    reference["technique"] = indicator.technique ?? NSNull()
                }
                if indicator.severity != original.severity || kept.contains("severity") {
                    reference["severity"] = indicator.severity.rawValue
                }
                entries.append(reference)
            } else {
                guard let data = try? JSONEncoder().encode(indicator),
                      let object = try? JSONSerialization.jsonObject(with: data) else { return nil }
                entries.append(object)
            }
        }
        let present = Set(indicators.map(\.id))
        let deleted = deleted.union(defaults.map(\.id)).subtracting(present)
        /// A kept reference whose identity an indicator here has now would name it twice.
        let references = unshipped.filter { !present.contains($0.id) }.map(\.entry)
        return ["entries": entries + references + undecodable, "deleted": deleted.map(\.uuidString).sorted()]
    }
}

