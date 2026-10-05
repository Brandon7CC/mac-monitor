//
//  ProcessLineageMode.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI


// MARK: - Process tree mode
/// Which parents the process tree in Event Facts' sidebar follows: one preference, chosen in the View menu
/// (``ProcessTreeCommands``) and in Settings > User Preferences (``ProcessTreePrefsView``). Each reads it through
/// `@AppStorage` under ``storageKey``, so the sidebar follows a change from either at once.
enum ProcessLineageMode: String, CaseIterable, Identifiable {
    /// Each process's Unix parent: the default.
    case unix
    /// Each process's launched-by parent: the process that really caused it to run (``LaunchedByParent``).
    case launchedByParent
    
    /// The `UserDefaults` key the choice is kept under.
    static let storageKey = "processLineageMode"
    /// The choice until one is made.
    static let defaultMode = ProcessLineageMode.unix
    
    var id: Self { self }
    
    /// The choice's name, in sentence case: "Unix parent" or "Launched by parent".
    var title: String {
        switch self {
        case .unix: "Unix parent"
        case .launchedByParent: "Launched by parent"
        }
    }
    
    /// The choice's View menu item, in title case: "Unix Parent" or "Launched by Parent".
    var menuTitle: String {
        switch self {
        case .unix: "Unix Parent"
        case .launchedByParent: "Launched by Parent"
        }
    }
    
    /// What the process tree shows with this choice, for a tooltip.
    var explanation: String {
        switch self {
        case .unix: "Event Facts' process tree follows each process's Unix parent."
        case .launchedByParent: "Event Facts' process tree follows the process that really launched each one."
        }
    }
    
    /// The choice's View menu shortcut, with Option-Command: U for Unix, L for Launched.
    var shortcut: KeyEquivalent {
        switch self {
        case .unix: "u"
        case .launchedByParent: "l"
        }
    }
}
