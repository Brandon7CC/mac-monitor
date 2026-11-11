//
//  IndicatorEditing.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - An editor's indicator
/// What Settings' editor opened: an indicator, and whether it's a new one, decided once as it opens. Saving sends
/// ``IndicatorEngine/change(_:from:)`` its ``original``, so an edit of an indicator another writer removed while the
/// editor was open is refused as an update rather than added back, whatever the set has by then.
public struct IndicatorEditing: Identifiable, Equatable {
    /// The indicator to start the editor from.
    public let indicator: Indicator
    /// The indicator as the set had it when the editor opened, or `nil` for a new one.
    public let original: Indicator?

    /// The editor's identity: its indicator's.
    public var id: UUID { indicator.id }

    /// Is it a new indicator, which the editor adds and can't delete?
    public var isNew: Bool { original == nil }

    /// - Parameter indicator: An indicator to add: from Add Indicator.
    /// - Returns: An editor for it, which adds it.
    public static func new(_ indicator: Indicator) -> IndicatorEditing {
        IndicatorEditing(indicator: indicator, original: nil)
    }

    /// - Parameter indicator: An indicator the set has: from Edit, a row's click or Show in Settings.
    /// - Returns: An editor for it, which only ever updates it.
    public static func existing(_ indicator: Indicator) -> IndicatorEditing {
        IndicatorEditing(indicator: indicator, original: indicator)
    }
}
