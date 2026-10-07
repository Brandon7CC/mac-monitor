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
/// Badge showing where a launched-by parent came from, such as "Launch Services". Styled like ``GroupLeaderView``.
///
/// VoiceOver reads the badge as "Launched by parent:" plus the source's name, with the source's explanation as the
/// hint.
struct LaunchedByParentBadge: View {
    /// The source shown.
    let source: LaunchedByParent.Source
    
    /// - Parameter launchedByParent: The launched-by parent whose source to show.
    init(_ launchedByParent: LaunchedByParent) {
        source = launchedByParent.source
    }
    
    var body: some View {
        HStack {
            Image(systemName: source.symbolName)
                .symbolRenderingMode(.palette)
                .foregroundColor(.black)
                .font(Font.system(size: 15, weight: .bold))
            Text("**`\(source.title)`**").foregroundColor(.black)
        }
        .padding(5.0)
        .background(RoundedRectangle(cornerSize: .init(width: 5.0, height: 5.0)).fill(helpfulProcessColor))
        .help("Launched by parent: \(source.explanation)")
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Launched by parent: \(source.title)")
        .accessibilityHint(source.explanation)
    }
}


// MARK: - Launched-by parent facts
/// A launched-by parent's facts: its source, its pid and executable, its launchd job, and who named it.
struct LaunchedByParentFacts: View {
    /// The launched-by parent and the event that created it, or `nil` when the store doesn't have the process's
    /// creator.
    let step: LaunchedByParentStep?
    /// The process whose launched-by parent this is (Markdown), when the facts don't sit beside it.
    var subject: LocalizedStringKey? = nil
    
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("**Launched by parent**").font(.title3)
                if let step { LaunchedByParentBadge(step.launchedByParent) }
            }
            if let subject { Text(subject).foregroundStyle(.secondary) }
            if let step {
                let answer = step.launchedByParent
                if let pid = answer.pid {
                    FactRow(name: "PID", value: String(pid))
                    FactRow(name: "Path", value: step.path, stacked: true)
                    if step.event == nil && !answer.isLaunchd {
                        Text("Its exec isn't in this trace.").font(.caption).foregroundStyle(.secondary)
                    }
                } else {
                    Text("Launch Services recorded no launcher, as for `open` run from a shell.")
                }
                if let label = answer.launchd_job?.label {
                    FactRow(name: "launchd job", value: label, stacked: true)
                }
                Text(answer.resolved_by.caption)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .help(answer.resolved_by.explanation)
            } else {
                Text("Not in this trace").foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}


// MARK: - Parent tab
/// The launched-by parent of the process an event is about, for the Parent tab: an exec's target, a fork's child, or
/// the process that caused any other event. Looked up in the store.
struct LaunchedByParentBox: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    
    /// The event.
    let message: ESMessage
    
    /// The process the event is about, by name and pid.
    private var subject: LocalizedStringKey {
        let name = message.created_name ?? message.initiating_name ?? "Unknown"
        return "Of `\(name)` (pid `\(String(message.created_pid?.int32Value ?? message.initiating_pid))`)"
    }
    
    var body: some View {
        GroupBox {
            let container = systemExtensionManager.coreDataContainer
            LaunchedByParentFacts(step: container.launchedByParents(of: message, limit: 1).first, subject: subject)
        }
    }
}
