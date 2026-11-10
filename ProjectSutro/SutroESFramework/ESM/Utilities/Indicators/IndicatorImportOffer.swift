//
//  IndicatorImportOffer.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - 3.0 indicators
/// The indicators a user kept in Mac Monitor 3.0, offered once to the Mac's set. Mac Monitor 3.1 keeps one set for
/// the Mac, which starts as Mac Monitor's own. Nothing of a user's 3.0 indicators reaches it unless they import them.
///
/// Only what's additive is offered:
/// - **Added:** the user's own indicators the Mac doesn't have. Each keeps its switches. So is an edited copy of one
///   this build no longer ships, as the Mac's own set keeps one.
/// - **Edited:** shipped indicators the user changed, other than by their switches, that differ from the Mac's. They
///   replace the Mac's versions only when the user opts in to that too, and each keeps whether the Mac's version is
///   on and where it shows. So is an edited copy of one this build no longer ships that the Mac already holds,
///   differently, as another user imported theirs.
///
/// A shipped indicator the user turned off or deleted is never carried over. Their `findings` user default is only
/// read, so going back to Mac Monitor 3.0 finds it as it was. Once the offer is taken or declined it isn't made again
/// (``offeredKey``).
public struct IndicatorImportOffer: Equatable {
    /// The user default Mac Monitor 3.0 kept its indicators in (``SavedIndicators``).
    public static let legacyKey = "findings"
    /// The user default that says the offer was taken or declined.
    public static let offeredKey = "indicatorsOffered"

    /// The user's own indicators the Mac doesn't have, in their order.
    public let added: [Indicator]
    /// The shipped indicators the user changed, each as it would replace the Mac's version, in their order.
    public let edited: [Indicator]

    /// - Parameters:
    ///   - data: The user's `findings` user default, or `nil`.
    ///   - mac: The Mac's indicators now.
    ///   - shipped: The indicators Mac Monitor ships.
    /// - Returns: `nil` when there's nothing to offer.
    public init?(legacy data: Data?, mac: [Indicator], shipped: [Indicator] = Indicator.defaults) {
        guard let legacy = data.flatMap({ SavedIndicators(data: $0, defaults: shipped) })?.indicators else {
            return nil
        }
        let original = Dictionary(shipped.map { ($0.id, $0) }) { first, _ in first }
        let current = Dictionary(mac.map { ($0.id, $0) }) { first, _ in first }
        added = legacy.filter { original[$0.id] == nil && current[$0.id] == nil }
        edited = legacy.compactMap { indicator -> Indicator? in
            if let shippedVersion = original[indicator.id], indicator.sameDetection(as: shippedVersion) {
                return nil
            }
            guard Indicator.isShippedIdentity(indicator.id),
                  let base = current[indicator.id] ?? original[indicator.id],
                  !indicator.sameDetection(as: base) else { return nil }
            var replacement = indicator
            replacement.isEnabled = base.isEnabled
            replacement.copyViews(from: base)
            return replacement
        }
        guard !added.isEmpty || !edited.isEmpty else { return nil }
    }

    /// The offer to show a user, if one is due.
    ///
    /// - Parameters:
    ///   - defaults: The user's defaults.
    ///   - mac: The Mac's indicators now.
    /// - Returns: `nil` once taken or declined, or when there's nothing to offer.
    public static func pending(in defaults: UserDefaults, mac: [Indicator]) -> IndicatorImportOffer? {
        guard !defaults.bool(forKey: offeredKey) else { return nil }
        return IndicatorImportOffer(legacy: defaults.data(forKey: legacyKey), mac: mac)
    }

    /// Don't make the offer again.
    ///
    /// - Parameter defaults: The user's defaults.
    public static func markOffered(in defaults: UserDefaults) {
        defaults.set(true, forKey: offeredKey)
    }

    /// - Parameter replacingEdited: Do the edited shipped indicators replace the Mac's versions?
    /// - Returns: The request that imports them: an add, so nothing else in the set changes.
    public func request(replacingEdited: Bool) -> IndicatorRequest {
        IndicatorRequest(.add, indicators: added + (replacingEdited ? edited : []))
    }
}
