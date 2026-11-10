//
//  UserFact.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/10/26.
//

import SwiftUI
import SutroESFramework


// MARK: - User fact
/// The user a process runs as in Event Facts: its effective user, and its real user before it when they differ.
/// A user with no name on this Mac, as a trace's users often are, shows its ID alone.
struct UserFact: View {
    /// The process: an event's own, or the one it acted on.
    let process: ESProcess

    var body: some View {
        HStack {
            if process.ruid != process.euid {
                Text("**Real:**")
                GroupBox { Text("`\(Self.label(process.ruid_human, process.ruid))`") }
                Image(systemName: "arrow.right")
                Text("**Effective:**")
            }
            GroupBox { Text("`\(Self.label(process.euid_human, process.euid))`") }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    /// - Parameters:
    ///   - name: The user's name, if this Mac knows one.
    ///   - id: The user's ID.
    /// - Returns: `name (id)`, or the ID alone.
    static func label(_ name: String?, _ id: Int64) -> String {
        guard let name, !name.isEmpty else { return "\(id)" }
        return "\(name) (\(id))"
    }
}
