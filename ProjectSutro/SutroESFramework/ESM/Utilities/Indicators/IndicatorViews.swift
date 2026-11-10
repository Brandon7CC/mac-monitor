//
//  IndicatorViews.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - One indicator's view switches
/// How the event tables mark an indicator's events, as one user sees them: the only part of an indicator that's per
/// user. Whether it's on, its predicate, name, symbol, color, explanation,
/// tactic, technique and severity are the Mac's, kept by the Security Extension.
public struct IndicatorViews: Codable, Equatable {
    /// How the event tables mark its events.
    public var tableMarks: Indicator.TableMarks

    /// - Parameter indicator: An indicator.
    public init(of indicator: Indicator) {
        tableMarks = indicator.tableMarks
    }

    private enum CodingKeys: String, CodingKey {
        case tableMarks
        /// The one mark 3.1's betas kept, still read.
        case tableMark
    }

    /// Decode a user's switches: the marks by name, or the one mark the betas kept
    /// (``Indicator/TableMarks/init(legacy:)``). The `showsInCorrelation` and `showsInGroups` they kept are ignored.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: When neither is there, or the mark isn't one.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let names = try container.decodeIfPresent([String].self, forKey: .tableMarks) {
            tableMarks = Indicator.TableMarks(names: names)
        } else if let marks = Indicator.TableMarks(legacy: try container.decode(String.self, forKey: .tableMark)) {
            tableMarks = marks
        } else {
            throw DecodingError.dataCorruptedError(forKey: .tableMark, in: container,
                                                   debugDescription: "It isn't a table mark.")
        }
    }

    /// Encode the switches, the marks by name.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: When they can't be encoded.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(tableMarks.names, forKey: .tableMarks)
    }
}


public extension Indicator {
    /// Where it shows, as one user sees it.
    var views: IndicatorViews {
        get { IndicatorViews(of: self) }
        set { tableMarks = newValue.tableMarks }
    }

    /// Take another indicator's view switches, and nothing else.
    ///
    /// - Parameter other: The indicator whose view switches to take.
    mutating func copyViews(from other: Indicator) {
        views = other.views
    }
}


// MARK: - The user's view switches
/// One user's view switches for the Mac's indicators, kept in their user defaults (``key``) by indicator identity.
/// An indicator without any shows as the Mac's set has it.
///
/// The first time it's read, a user who changed indicators in Mac Monitor 3.0 (the `findings` user default) keeps the
/// view switches they chose there: those of their own indicators, and of shipped ones they changed. The `findings`
/// default is only read, never written, so Mac Monitor 3.0 still finds it.
public struct IndicatorOverlay: Equatable {
    /// The user default that keeps them, as a JSON object of identity to switches.
    public static let key = "indicators.views"

    /// The view switches, by indicator identity.
    public private(set) var views: [UUID: IndicatorViews]

    /// - Parameter views: The view switches, by indicator identity.
    public init(_ views: [UUID: IndicatorViews] = [:]) {
        self.views = views
    }

    /// The user's view switches, or, the first time, those they chose in Mac Monitor 3.0.
    ///
    /// - Parameters:
    ///   - defaults: Where they're kept.
    ///   - shipped: The indicators Mac Monitor ships, whose 3.0 switches are kept only where they were changed.
    public init(defaults: UserDefaults, shipped: [Indicator] = Indicator.defaults) {
        if let data = defaults.data(forKey: Self.key) {
            let saved = (try? JSONDecoder().decode([String: IndicatorViews].self, from: data)) ?? [:]
            let pairs = saved.compactMap { key, value in UUID(uuidString: key).map { ($0, value) } }
            views = Dictionary(pairs) { first, _ in first }
        } else {
            self = Self.legacy(defaults.data(forKey: IndicatorImportOffer.legacyKey), shipped: shipped)
            save(to: defaults)
        }
    }

    /// The view switches a Mac Monitor 3.0 user chose.
    ///
    /// - Parameters:
    ///   - data: Their `findings` user default, or `nil`.
    ///   - shipped: The indicators Mac Monitor ships.
    /// - Returns: The switches of each of their own indicators, and of each shipped one whose switches they changed.
    static func legacy(_ data: Data?, shipped: [Indicator]) -> IndicatorOverlay {
        guard let indicators = data.flatMap({ SavedIndicators(data: $0, defaults: shipped) })?.indicators else {
            return IndicatorOverlay()
        }
        let original = Dictionary(shipped.map { ($0.id, $0.views) }) { first, _ in first }
        return IndicatorOverlay(Dictionary(indicators.compactMap { indicator in
            original[indicator.id] == indicator.views ? nil : (indicator.id, indicator.views)
        }) { first, _ in first })
    }

    /// - Parameter defaults: Where to keep them.
    public func save(to defaults: UserDefaults) {
        let object = Dictionary(uniqueKeysWithValues: views.map { ($0.key.uuidString, $0.value) })
        defaults.set(try? JSONEncoder().encode(object), forKey: Self.key)
    }

    /// - Parameter indicators: The Mac's indicators, in order.
    /// - Returns: Them as this user sees them.
    public func applied(to indicators: [Indicator]) -> [Indicator] {
        guard !views.isEmpty else { return indicators }
        return indicators.map { indicator in
            guard let views = views[indicator.id] else { return indicator }
            var indicator = indicator
            indicator.views = views
            return indicator
        }
    }

    /// Keep an indicator's view switches as this user's, or forget them when they're the Mac's again, so a switch
    /// turned off and back on leaves nothing behind.
    ///
    /// - Parameters:
    ///   - indicator: The indicator, as the user set it.
    ///   - mac: The indicator as the Mac's set has it, or `nil` when the set doesn't have it yet.
    /// - Returns: Did this user's switches change?
    @discardableResult
    public mutating func keep(_ indicator: Indicator, mac: Indicator?) -> Bool {
        let kept = indicator.views == mac?.views ? nil : indicator.views
        guard views[indicator.id] != kept else { return false }
        views[indicator.id] = kept
        return true
    }

    /// Forget every view switch, as Restore Defaults does.
    public mutating func removeAll() {
        views = [:]
    }
}
