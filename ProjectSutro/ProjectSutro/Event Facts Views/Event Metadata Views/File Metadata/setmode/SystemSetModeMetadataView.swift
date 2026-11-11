//
//  SystemSetModeMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/29/25.
//

import SwiftUI
import SutroESFramework

/// What a `setmode` event says: the mode a file was given, what it added worth pointing out, and the mode it had.
struct SystemSetModeMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.setmode {
            /// The mode the file had: Endpoint Security's stat of the target is from before the change.
            let previousMode = event.previousFileMode
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    HStack {
                        Text("\u{2022} **Mode:**")
                        FileModeFact(mode: event.fileMode)
                        ForEach(event.addedCallouts, id: \.self) { callout in
                            FileModeCalloutBadge(callout: callout, previousIsKnown: previousMode != nil)
                        }
                    }

                    if let previousMode {
                        HStack {
                            Text("\u{2022} **Previous mode:**")
                            FileModeFact(mode: previousMode)
                        }
                    }

                    if let path = event.target.path {
                        HStack {
                            FileExistsLabel(title: "**File path:**", path: path)
                            GroupBox {
                                Text("`\(path)`")
                                    .lineLimit(10)
                            }
                            ShowInFinderButton(path: path)
                        }
                    }
                }
            }
        }
    }
}


// MARK: - Mode and callouts
/// A file mode as octal and symbols, such as "0644 rw-r--r--", with its value in decimal on hover.
struct FileModeFact: View {
    let mode: FileMode

    var body: some View {
        GroupBox {
            Text(mode.label)
                .monospaced()
        }
        .help("\(mode.permissions) in decimal")
    }
}

/// What a setmode added that's worth pointing out, beside the new mode.
struct FileModeCalloutBadge: View {
    let callout: FileModeCallout
    /// Whether the target's stat gave the mode before the change. Without it, the badge is for what the new mode sets.
    let previousIsKnown: Bool

    /// The badge's text and color: red for setuid and setgid, orange for the rest.
    private var style: (text: String, color: Color, help: String) {
        switch callout {
        case .madeExecutable:
            return ("Executable", .orange,
                    "Gave the file an execute bit, as chmod +x does: a downloaded file is made executable to run it.")
        case .setuidAdded:
            return ("Setuid", .red, "Added setuid: the file runs as its owner, whoever runs it.")
        case .setgidAdded:
            return ("Setgid", .red, "Added setgid: the file runs as its group, whoever runs it.")
        case .worldWritable:
            return ("World-writable", .orange, "Added write for everyone: anyone on this Mac can write to the file.")
        }
    }

    var body: some View {
        CalloutBadge(text: style.text, color: style.color,
                     help: previousIsKnown ? style.help
                        : style.help + " The mode before the change isn't known, so the file may have had it already.")
    }
}
