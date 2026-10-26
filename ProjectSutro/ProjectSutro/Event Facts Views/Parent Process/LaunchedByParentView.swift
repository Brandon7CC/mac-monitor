//
//  LaunchedByParentView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Names
extension LaunchedByParent.Source {
    /// The source's name in Event Facts.
    var title: String {
        switch self {
        case .unixParent: "Unix parent"
        case .responsibleProcess: "Responsible process"
        case .launchdJob: "launchd job"
        case .launchServices: "Launch Services"
        }
    }
    
    /// The source's SF Symbol.
    var symbolName: String {
        switch self {
        case .unixParent: "arrow.turn.down.right"
        case .responsibleProcess: "checkmark.shield"
        case .launchdJob: "gearshape.2"
        case .launchServices: "paperplane"
        }
    }
    
    /// What the source means, for a tooltip.
    var explanation: String {
        switch self {
        case .unixParent:
            "The process's Unix parent (launchd itself when nothing better is known), or the parent it had when "
                + "launchd adopted it before its exec."
        case .responsibleProcess:
            "The process macOS holds responsible for this one, such as an XPC service's host app."
        case .launchdJob:
            "launchd started this process as the job its XPC_SERVICE_NAME names."
        case .launchServices:
            "The process that asked LaunchServices to launch this app, such as Finder, the Dock or another app."
        }
    }
}

extension LaunchedByParent.ResolvedBy {
    /// Who named the launched-by parent, as a caption.
    var caption: String {
        switch self {
        case .securityExtension: "Stamped by the Security Extension"
        case .app: "Named by Mac Monitor"
        case .import: "Computed when the trace was opened"
        }
    }
    
    /// When, and from what, for a tooltip.
    var explanation: String {
        switch self {
        case .securityExtension:
            "The Security Extension named it while recording the event. For an app, it asked Launch Services who "
                + "launched it."
        case .app:
            "Mac Monitor named it after the event arrived from an older Security Extension, which didn't name one."
        case .import:
            "Mac Monitor named it from the trace's own events when the trace was opened."
        }
    }
}


// MARK: - Badge
/// Launched-by parent badge, styled like ``GroupLeaderView``. Shows the launcher's name (e.g., "Dock"), or the
/// source (e.g., "Launch Services") with `showsSource`.
struct LaunchedByParentBadge: View {
    /// The launched-by parent to show.
    let launchedByParent: LaunchedByParent
    /// Show the source instead of the launcher.
    var showsSource = false
    
    private var source: LaunchedByParent.Source { launchedByParent.source }
    
    /// The launcher's name, else its pid. `nil` when no launcher was recorded.
    private var launcherName: String? {
        if let name = (launchedByParent.path?.lastPathComponent).nonEmpty { return name }
        return launchedByParent.pid.map { "pid \($0)" }
    }
    
    private var text: String {
        showsSource ? source.title : launcherName ?? source.title
    }
    
    /// e.g., "Launched by Dock (pid 1350) through Launch Services."
    private var summary: String {
        guard let name = launcherName else { return "Launched through \(source.title). No launcher was recorded." }
        let pid = launchedByParent.pid.map { " (pid \($0))" } ?? ""
        return "Launched by \(name)\(name.hasPrefix("pid ") ? "" : pid) through \(source.title)."
    }
    
    var body: some View {
        HStack {
            Image(systemName: source.symbolName)
                .symbolRenderingMode(.palette)
                .foregroundColor(.black)
                .font(Font.system(size: 15, weight: .bold))
            Text("**`\(text)`**").foregroundColor(.black)
        }
        .padding(5.0)
        .background(RoundedRectangle(cornerSize: .init(width: 5.0, height: 5.0)).fill(helpfulProcessColor))
        .help("\(summary) \(source.explanation)")
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(summary)
        .accessibilityHint(source.explanation)
    }
}


// MARK: - Launched-by parent facts
/// The launched-by parent of the process an event is about, for the Parent tab: an exec's target, a fork's child, or
/// the process that caused any other event, looked up in the store. Shows its source, its pid and executable, and its
/// launchd job. Who named it, and whether its exec is in the trace, are in the heading's tooltip.
struct LaunchedByParentFacts: View {
    /// The event.
    let message: ESMessage
    
    var body: some View {
        GroupBox {
            /// The launched-by parent and the event that created it, or `nil` when the store doesn't have the
            /// process's creator.
            let step = CoreDataController.shared.lineage.launchedByParents(of: message, limit: 1).first
            VStack(alignment: .leading) {
                HStack {
                    Text("**Launched by parent**").font(.title3)
                    if let step { LaunchedByParentBadge(launchedByParent: step.launchedByParent, showsSource: true) }
                }
                .help(details(step) ?? "")
                if let step {
                    let answer = step.launchedByParent
                    if let pid = answer.pid {
                        FactRow(name: "PID", value: String(pid))
                        FactRow(name: "Path", value: step.path, stacked: true)
                    } else {
                        Text("Launch Services recorded no launcher, as for `open` run from a shell.")
                    }
                    if let label = answer.launchd_job?.label {
                        FactRow(name: "launchd job", value: label, stacked: true)
                    }
                } else {
                    Text("Not in this trace").foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
    
    /// Who named the launched-by parent and how, and whether its exec is in the trace, for the heading's tooltip.
    ///
    /// - Parameter step: The launched-by parent and the event that created it, if the store has it.
    /// - Returns: The tooltip, or `nil` without a launched-by parent.
    private func details(_ step: LaunchedByParentStep?) -> String? {
        guard let step else { return nil }
        let answer = step.launchedByParent
        let notInTrace = answer.pid != nil && step.event == nil && !answer.isLaunchd
        return "\(answer.resolved_by.caption). \(answer.resolved_by.explanation)"
            + (notInTrace ? " Its exec isn't in this trace." : "")
    }
}
