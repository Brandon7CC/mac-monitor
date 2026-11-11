//
//  SavedSetState.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Saved set state
/// Whether a saved set kept in a root-owned file (``RootFileStore``), such as ``SavedMuteSet``, can be changed.
enum SavedSetState: Equatable, Sendable {
    /// Changes are saved.
    case writable
    /// The file was written by a newer Mac Monitor, and is kept as it is. The set decides which changes, if any, may
    /// still overwrite it: the saved mute set allows only Reset.
    case readOnly(version: Int)
    /// The directory can't be trusted: nothing is saved.
    case unavailable(reason: String)
}
