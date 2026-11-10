//
//  IndicatorSeverity.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Severity
/// How strong a sign of something malicious an indicator's match is. It's part of the detection: Mac-wide, saved
/// with the indicator, and in every record that lists it. It never changes what matches.
public enum IndicatorSeverity: String, Codable, CaseIterable, Comparable, Sendable {
    /// Context, and signals that are often benign.
    case low
    /// Suspicious behavior that has benign uses.
    case medium
    /// A strong sign of malicious activity.
    case high

    /// Its name, as Settings shows it.
    public var name: String {
        switch self {
        case .low: "Low"
        case .medium: "Medium"
        case .high: "High"
        }
    }

    /// Lower severities first.
    ///
    /// - Parameters:
    ///   - lhs: A severity.
    ///   - rhs: Another.
    /// - Returns: Whether `lhs` is the lower.
    public static func < (lhs: IndicatorSeverity, rhs: IndicatorSeverity) -> Bool {
        lhs.rank < rhs.rank
    }

    /// Its place, lowest first.
    private var rank: Int {
        switch self {
        case .low: 0
        case .medium: 1
        case .high: 2
        }
    }
}


// MARK: - Ordering
public extension Indicator {
    /// Indicators as Event Facts' Indicators popover lists them: High first, then Medium, then Low, and by name
    /// within each, as Finder sorts names.
    ///
    /// - Parameter indicators: The indicators.
    /// - Returns: Them, in that order.
    static func bySeverity(_ indicators: [Indicator]) -> [Indicator] {
        indicators.sorted { first, second in
            guard first.severity == second.severity else { return first.severity > second.severity }
            return first.name.localizedStandardCompare(second.name) == .orderedAscending
        }
    }
}
