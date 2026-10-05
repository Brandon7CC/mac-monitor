//
//  ThreadStateFactsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Thread state facts
/// A `remote_thread_create` event's thread state in Event Facts: its flavor, and the state's bytes in hex.
struct ThreadStateFactsView: View {
    /// The event's thread state: `nil` when Endpoint Security gave none (`thread_create`).
    let state: ThreadState?
    /// The name of the state's flavor, if Mac Monitor knows it.
    let flavorName: String?
    
    var body: some View {
        if let state {
            FactRow(name: "Thread state flavor", value: flavor(of: state), style: .monospaced)
            if let bytes = state.stateBytes {
                DisclosureGroup {
                    /// Formatted only while the group is open.
                    GroupBox {
                        Text((state.hexRows() ?? []).joined(separator: "\n"))
                            .monospaced()
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                } label: {
                    Text("**Thread state:** \(bytes.count) bytes")
                }.padding([.leading], 5.0)
            } else {
                FactRow(name: "Thread state", value: "Not recorded", style: .monospaced)
                    .help("eslogger doesn't write a thread state's bytes, and Mac Monitor recorded none before 2.2.0.")
            }
        } else {
            FactRow(name: "Thread state", value: "None", style: .monospaced)
                .help("Endpoint Security gives a thread state only for thread_create_running.")
        }
    }
    
    /// A flavor's name and number, or its number alone when Mac Monitor doesn't know its name.
    ///
    /// - Parameter state: The thread state.
    /// - Returns: The flavor, as its row shows it.
    private func flavor(of state: ThreadState) -> String {
        flavorName.map { "\($0) (\(state.flavor))" } ?? "\(state.flavor)"
    }
}
