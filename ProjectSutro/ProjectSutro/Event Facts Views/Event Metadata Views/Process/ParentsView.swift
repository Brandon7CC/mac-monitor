//
//  ParentsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Parent rows
/// The Unix parent and launched-by parent of the process an exec or fork created.
///
/// These show as rows under "Parent user" in the Parent process details. We only show the launched-by parent when
/// it's different from the Unix parent.
struct ParentsView: View {
    /// The parents.
    let parents: ProcessParents

    var body: some View {
        VStack(alignment: .leading) {
            ParentRow(
                title: LaunchedByParent.Source.unixParent.title,
                systemImage: LaunchedByParent.Source.unixParent.symbolName,
                path: parents.unix.path,
                pid: parents.unix.pid
            ) {
                if parents.unix.original_ppid != parents.unix.pid {
                    Text("\u{2022} **Original parent PID:**")
                    GroupBox { Text("`\(String(parents.unix.original_ppid))`") }
                }
            }
            .help(LaunchedByParent.Source.unixParent.explanation)

            if let step = parents.launchedByParent, !parents.launchedByParentIsUnixParent {
                launchedByParent(step)
            }
        }
    }

    /// Rows for the launched-by parent: its source, executable and pid, then its launchd job if it has one.
    ///
    /// - Parameter step: The launched-by parent and the event that created it.
    /// - Returns: The rows.
    @ViewBuilder
    private func launchedByParent(_ step: LaunchedByParentStep) -> some View {
        let answer = step.launchedByParent
        let notInTrace = answer.pid != nil && step.event == nil && !answer.isLaunchd
        ParentRow(
            title: answer.source.title,
            systemImage: answer.source.symbolName,
            path: answer.pid == nil ? "No launcher recorded" : step.path,
            pid: answer.pid
        )
        .help(
            "Launched by parent: \(answer.source.explanation)"
                + (notInTrace ? " Its exec isn't in this trace." : "")
                + " \(answer.resolved_by.caption)."
        )

        if let label = answer.launchd_job?.label {
            HStack {
                Text("\u{2022} **launchd job:**")
                GroupBox { Text("`\(label)`").lineLimit(30) }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}


// MARK: - One parent
/// One parent formatted like the "Parent user" row. Shows the executable path, then the pid and any extra facts.
private struct ParentRow<Trailing: View>: View {
    /// The row's label, without a colon.
    let title: String
    /// The label's SF Symbol.
    let systemImage: String
    /// The parent's executable, or `nil` for "Unknown".
    let path: String?
    /// The parent's pid, when known.
    let pid: Int32?
    /// Extra facts shown after the pid
    @ViewBuilder var trailing: () -> Trailing

    /// - Parameters:
    ///   - title: The row's label, without a colon.
    ///   - systemImage: The label's SF Symbol.
    ///   - path: The parent's executable, or `nil` for "Unknown".
    ///   - pid: The parent's pid, when known.
    ///   - trailing: Extra facts shown after the pid.
    init(title: String, systemImage: String, path: String?, pid: Int32?,
         @ViewBuilder trailing: @escaping () -> Trailing = { EmptyView() }) {
        self.title = title
        self.systemImage = systemImage
        self.path = path
        self.pid = pid
        self.trailing = trailing
    }

    var body: some View {
        HStack {
            Label("**\(title):**", systemImage: systemImage)
            GroupBox { Text("`\(path ?? "Unknown")`").lineLimit(30) }
            if let pid {
                Text("\u{2022} **PID:**")
                GroupBox { Text("`\(String(pid))`") }
            }
            trailing()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}


// MARK: - Looked up
/// Looks up the parent rows of an exec or fork in the store. Shows nothing for other events.
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
