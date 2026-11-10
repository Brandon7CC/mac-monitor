//
//  IndicatorAlertLimits.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - How often notifications come
/// The numbers that bound how often indicator matches notify (``IndicatorAlertCoalescer``), in seconds. The shipped
/// ones (``standard``) keep a 14-indicator Medium flood to about 38 notifications in its first hour, and still post a
/// High, or a Medium never seen before, at once.
public struct IndicatorAlertLimits: Sendable {
    /// An indicator's first window: how long after a notice its later matches are gathered into one summary.
    public var firstWindow: TimeInterval = 60
    /// The longest window. Each window that ends with matches folded into it doubles the next, up to this.
    public var maxWindow: TimeInterval = 900
    /// An indicator with no match for this long starts over at ``firstWindow``.
    public var idleReset: TimeInterval = 900
    /// How many Medium notices may post at once.
    public var mediumBurst: Double = 3
    /// One Medium token comes back this often.
    public var mediumRefill: TimeInterval = 120
    /// The Medium tokens a summary needs (it takes one), so one is always left for an indicator's first notice.
    public var mediumSummaryNeeds: Double = 2
    /// How many High notices may post at once. High has its own tokens, so no Medium storm can hold one back.
    public var highBurst: Double = 5
    /// One High token comes back this often.
    public var highRefill: TimeInterval = 30
    /// How long the overflow summary gathers after its first match.
    public var overflowGather: TimeInterval = 10
    /// The least time between overflow summaries, doubled while it keeps filling.
    public var overflowFirstInterval: TimeInterval = 60
    /// The most time between overflow summaries.
    public var overflowMaxInterval: TimeInterval = 900
    /// How many indicators are tracked. Past this, the one matched least recently is forgotten.
    public var trackedIndicators = 256
    /// A Medium event older than this goes only to the overflow summary.
    public var staleAfter: TimeInterval = 120
    /// An event older than this says when it happened.
    public var showsTimeAfter: TimeInterval = 60
    /// The most distinct processes a summary counts.
    public var distinctProcesses = 16
    /// The most indicators the overflow summary names.
    public var overflowListed = 3

    /// The shipped numbers.
    public static let standard = IndicatorAlertLimits()

    /// The shipped numbers.
    public init() {}
}
