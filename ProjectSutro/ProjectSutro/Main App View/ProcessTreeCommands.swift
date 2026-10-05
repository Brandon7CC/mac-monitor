//
//  ProcessTreeCommands.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI


// MARK: - View menu: process tree
/// The View menu's process tree items: which parents Event Facts' process tree follows. Under a "Process tree"
/// heading, after the table views, "Unix Parent" (Option-Command-U) and "Launched by Parent" (Option-Command-L) are
/// checked like a pair of radio buttons: choosing one checks it and unchecks the other.
///
/// Settings > User Preferences makes the same choice (``ProcessTreePrefsView``): both are kept under
/// ``ProcessLineageMode/storageKey``.
struct ProcessTreeCommands: Commands {
    /// The choice: the app's `@AppStorage` under ``ProcessLineageMode/storageKey``.
    @Binding var mode: ProcessLineageMode
    
    var body: some Commands {
        CommandGroup(after: .sidebar) {
            Divider()
            
            Text("Process tree")
            ForEach(ProcessLineageMode.allCases) { choice in
                Toggle(choice.menuTitle, isOn: isChosen(choice))
                    .keyboardShortcut(choice.shortcut, modifiers: [.command, .option])
                    .help(choice.explanation)
            }
        }
    }
    
    /// Whether a choice is the one made, as a menu item's check mark. Checking it makes it the choice; unchecking the
    /// choice made does nothing, so one item is always checked.
    ///
    /// - Parameter choice: The item's choice.
    /// - Returns: The item's binding.
    private func isChosen(_ choice: ProcessLineageMode) -> Binding<Bool> {
        Binding(get: { mode == choice }, set: { if $0 { mode = choice } })
    }
}
