//
//  ParentsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Parents box
/// The Unix parent and the launched-by parent of the process an exec or fork created, side by side, or as one when the
/// launched-by parent is the Unix parent.
struct ParentsView: View {
    /// The parents.
    let parents: ProcessParents
    
    var body: some View {
        GroupBox {
            VStack(alignment: .leading) {
                Label("**Parents**", systemImage: "person.2")
                    .font(.title3)
                if parents.launchedByParentIsUnixParent, let answer = parents.launchedByParent?.launchedByParent {
                    unixParent(titled: "Unix parent and launched by parent")
                    Text(answer.resolved_by.caption)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .help(answer.resolved_by.explanation)
                } else {
                    HStack(alignment: .top) {
                        unixParent(titled: "Unix parent")
                        Divider()
                        LaunchedByParentFacts(step: parents.launchedByParent)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
    
    /// The Unix parent's facts: its pid, its executable, and the original parent's pid when launchd adopted the
    /// process.
    ///
    /// - Parameter title: The column's title.
    /// - Returns: The facts.
    private func unixParent(titled title: String) -> some View {
        VStack(alignment: .leading) {
            Text(title).font(.title3).bold()
            FactRow(name: "PID", value: String(parents.unix.pid))
            FactRow(name: "Path", value: parents.unix.path, stacked: true)
            if parents.unix.original_ppid != parents.unix.pid {
                FactRow(name: "Original parent PID", value: String(parents.unix.original_ppid))
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}


// MARK: - Looked up
/// The Parents box of an exec or fork, looked up in the store. Nothing for any other event.
struct ParentsBox: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    
    /// The exec or fork.
    let message: ESMessage
    
    var body: some View {
        if let parents = systemExtensionManager.coreDataContainer.parents(of: message) {
            ParentsView(parents: parents)
        }
    }
}
