//
//  ProcessTreePrefsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI


// MARK: - Process tree preferences
/// User Preferences' process tree settings: which parents Event Facts' process tree follows, the same choice the View
/// menu makes (``ProcessTreeCommands``), and whether forks count as Unix parents.
struct ProcessTreePrefsView: View {
    @EnvironmentObject var userPrefs: UserPrefs
    /// Which parents the tree follows.
    @AppStorage(ProcessLineageMode.storageKey) private var mode = ProcessLineageMode.defaultMode
    
    var body: some View {
        VStack(alignment: .leading) {
            Picker(selection: $mode) {
                ForEach(ProcessLineageMode.allCases) { choice in
                    Text(choice.title).tag(choice)
                }
            } label: {
                Text("Process tree").bold()
            }
            .pickerStyle(.radioGroup)
            .horizontalRadioGroupLayout()
            .fixedSize()
            
            Text("\(mode.explanation) The View menu chooses it too.")
            
            Divider()
            
            HStack {
                Toggle("Forks as parents", isOn: userPrefs.$forksAsParent)
                    .bold()
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            
            Text("Show forks as parents in process subtrees by Unix parent.")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
