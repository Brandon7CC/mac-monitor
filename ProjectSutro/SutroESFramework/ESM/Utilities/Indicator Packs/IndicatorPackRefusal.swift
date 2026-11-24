//
//  IndicatorPackRefusal.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/16/26.
//

import Foundation


// MARK: - Pack refusal
/// Why a signed pack wasn't installed (``SavedIndicatorSet``). The installed indicators stay as they were.
public enum IndicatorPackRefusal: Error, Equatable, CustomStringConvertible {
    /// Its signature wasn't accepted (``IndicatorPackVerifier``): why, as the user reads it.
    case signature(String)
    /// Its payload isn't a pack this build reads (``IndicatorPack/decode(_:)``): why.
    case payload(String)
    /// It isn't a later release than the indicators this Mac has: its sequence, theirs, and where they come from.
    case notNewer(offered: Int, current: Int, source: IndicatorBaseline.Source)
    /// One of its indicators this build should run doesn't compile: its name, and why.
    case cannotRun(name: String, reason: String)
    /// With it, the Mac's set would be past a limit (``IndicatorLimits``): which.
    case pastLimit(String)
    /// It couldn't be kept: why.
    case storage(String)
    /// It isn't the release the caller checked before asking to install it: its sequence, and the one checked.
    case changed(offered: Int, expected: Int)
    /// The Security Extension stopped more than once while it was checking this very file, so it's passed over.
    case stoppedTheExtension

    /// The refusal, as the user reads it.
    public var description: String {
        switch self {
        case .signature(let reason):
            "The pack wasn't installed. \(reason)"
        case .payload(let reason):
            "The pack is signed, but it isn't one this Mac Monitor installs. \(reason)"
        case .notNewer(let offered, let current, .installed) where offered == current:
            "Pack \(offered) is already installed."
        case .notNewer(let offered, let current, .installed):
            "Pack \(offered) is older than pack \(current), which is installed."
        case .notNewer(let offered, let current, .linked):
            "Pack \(offered) isn't newer than the indicators this Mac Monitor came with (pack \(current))."
        case .cannotRun(let name, let reason):
            "The pack wasn't installed, because this Mac Monitor can't run its indicator “\(name)”. \(reason)"
        case .pastLimit(let reason):
            "The pack wasn't installed, because this Mac's indicators would be past a limit with it. \(reason)"
        case .storage(let reason):
            "The pack couldn't be kept, so nothing changed. \(reason)"
        case .changed(let offered, let expected):
            "Pack \(offered) is out now, not pack \(expected), which was checked. Check again before installing."
        case .stoppedTheExtension:
            "The Security Extension stopped twice while it was checking this pack, so it's passed over. A later "
                + "pack is still looked for."
        }
    }
}
