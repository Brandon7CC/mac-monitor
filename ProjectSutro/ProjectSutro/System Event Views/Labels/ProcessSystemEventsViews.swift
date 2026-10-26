//
//  ProcessSystemEventsViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework


/// An exec's process name in the Process Execution table. Its built-in marks come first (``Finding/nameMarks``), then
/// the findings that mark it (Settings ▸ Findings), then how it's signed. A name without a signing ID is bold.
struct ProcessExecEventNameView: View {
    var message: ESMessage

    /// Nothing for an exec that's gone, as a Clear's events are while the tables let go of them.
    var body: some View {
        if let exec = message.event.exec {
            let name = (exec.target.executable?.path ?? "").lastPathComponent
            HStack {
                BuiltInMarks(message: message, marks: Finding.nameMarks)
                FindingMarks(message: message)
                BuiltInMarks(message: message, marks: Finding.nameSignatureMarks)
                if exec.target.hasSigningID {
                    Label(name, systemImage: "checkmark.seal")
                } else {
                    Label("**\(name)**", systemImage: "xmark.seal")
                        .eventLabelLook(EventLabelLook(signatureOf: exec.target))
                }
            }
            .frame(alignment: .leading)
        }
    }
}
