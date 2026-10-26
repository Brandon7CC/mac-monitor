//
//  ProcessSystemEventsViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework
import OSLog


/// An exec's process name in the event tables, after what's worth knowing about it, as its Event Facts label shows:
/// root or elevated, a dyld injection, File Quarantine awareness, the findings that mark it
/// (Settings ▸ Findings), such as a new executable or a script, then how it's signed.
struct ProcessExecEventNameView: View {
    var message: ESMessage

    /// Nothing for an exec that's gone, as a Clear's events are while the tables let go of them.
    var body: some View {
        if let exec = message.event.exec {
            name(exec)
        }
    }

    /// - Parameter exec: The exec.
    /// - Returns: Its icons, then its process name, as it's signed.
    private func name(_ exec: ESProcessExecEvent) -> some View {
        let procName = (exec.target.executable?.path ?? "").lastPathComponent
        return HStack {
            indicators(exec)
            if exec.target.is_adhoc_signed {
                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette)
                    .foregroundStyle(.black, .orange).help("Binary is adhoc signed!")
                Label("**\(procName)**", systemImage: "xmark.seal").symbolRenderingMode(.palette).foregroundStyle(.orange)
            } else if (exec.target.signing_id.nonEmpty ?? "Unknown") == "Unknown" {
                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette)
                    .foregroundStyle(.black, .red).help("Unknown signing ID")
                Label("**\(procName)**", systemImage: "xmark.seal").symbolRenderingMode(.palette).foregroundStyle(.red)
            } else {
                Label(procName, systemImage: "checkmark.seal")
            }
        }
        .frame(alignment: .leading)
    }

    /// - Parameter exec: The exec.
    /// - Returns: Every exec's icons, whatever its signature.
    @ViewBuilder
    private func indicators(_ exec: ESProcessExecEvent) -> some View {
        if exec.target.ruid == 0 {
            Image(systemName: "person.crop.circle.badge.exclamationmark.fill").symbolRenderingMode(.multicolor)
                .padding([.leading], 2.0).help("Process is running as the root user")
        } else if exec.target.ruid != exec.target.euid && exec.target.euid == 0 {
            Image(systemName: "key.radiowaves.forward.fill").symbolRenderingMode(.multicolor)
                .padding([.leading], 2.0).help("Process elevated to root!")
        }
        if exec.env.joined().lowercased().contains("dyld_insert_libraries") {
            Image(systemName: "bookmark.slash").help("Dyld injection attempt.").symbolRenderingMode(.palette)
                .foregroundStyle(.red)
        }
        /// The process is File Quarantine-aware: `LSFileQuarantineEnabled` in its `Info.plist`.
        if exec.target.file_quarantine_type != "DISABLED" {
            Image(systemName: "lock.icloud").symbolRenderingMode(.multicolor).padding([.leading], 2.0)
                .help("Process is File Quarantine-aware.")
        }
        FindingMarks(message: message)
    }
}
