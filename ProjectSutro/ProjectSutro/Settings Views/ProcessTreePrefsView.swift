//
//  ProcessTreePrefsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI


// MARK: - Process tree preferences
/// Settings ▸ General's process tree setting: which parents Event Facts' process tree follows, the same choice the
/// View menu makes (``ProcessTreeCommands``).
struct ProcessTreePrefsView: View {
    /// Which parents the tree follows.
    @AppStorage(ProcessLineageMode.storageKey) private var mode = ProcessLineageMode.defaultMode
    
    var body: some View {
        Picker("Follows", selection: $mode) {
            ForEach(ProcessLineageMode.allCases) { choice in
                Text(choice.title).tag(choice)
            }
        }
        .pickerStyle(.radioGroup)
        Text("\(mode.explanation) The View menu chooses it too.")
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }
}
