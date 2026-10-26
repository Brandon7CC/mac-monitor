//
//  ParentsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Parent rows
/// An exec's or fork's Unix parent and launched-by parent rows under "Parent user", looked up in the store. The
/// launched-by parent only shows when it differs.
struct ParentsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager

    /// The exec or fork.
    let message: ESMessage

    var body: some View {
        if let parents = systemExtensionManager.coreDataContainer.parents(of: message) {
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
    }

    /// The launched-by parent's rows.
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
/// One parent, formatted like the "Parent user" row.
private struct ParentRow<Trailing: View>: View {
    let title: String
    let systemImage: String
    let path: String?
    let pid: Int32?
    /// Shown after the pid
    @ViewBuilder var trailing: () -> Trailing

    /// - Parameters:
    ///   - title: The row's label, without a colon.
    ///   - systemImage: The label's SF Symbol.
    ///   - path: The parent's executable, or `nil` for "Unknown".
    ///   - pid: The parent's pid, when known.
    ///   - trailing: Shown after the pid.
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
