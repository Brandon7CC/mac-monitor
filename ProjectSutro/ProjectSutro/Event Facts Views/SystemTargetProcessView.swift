//
//  SystemTargetProcessView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

public let helpfulProcessColor: Color = Color(cgColor: .init(red: 43/255.0, green: 145/255.0, blue: 217/255.0, alpha: 1.0))


/// Metadata includes:
/// - The launched-by parent (e.g., "Dock") when it isn't the Unix parent
/// - Group Leader
struct AdditionalProcMetadataView: View {
    var selectedMessage: ESMessage
    
    
    var body: some View {
        if let exec = selectedMessage.event.exec {
            if let parent = exec.launched_by_parent, parent.source != .unixParent {
                LaunchedByParentBadge(launchedByParent: parent)
            }
            
            if exec.target.group_id == exec.target.pid {
                GroupLeaderView()
            }
        }
    }
}

struct FileQuarantineLabelView: View {
    var type: String
    
    var helpText: String {
        switch(type) {
        case "OPT_IN":
           return "This process is being run as part of a \"File Quarantine-aware\" app. Files created by this process should be quarantined."
        case "FORCED":
            return "This process has not opted into File Quarantine. However, Apple has forced them in."
        default:
            return "UNKNOWN"
        }
    }
    
    var body: some View {
        Group {
            HStack {
                Image(systemName: "lock.shield").symbolRenderingMode(.palette).foregroundColor(.black).font(Font.system(size: 15, weight: .bold))
                switch(type) {
                case "FORCED":
                    Text("**`Forced Quarantine`**").foregroundColor(.black)
                default:
                    Text("**`File Quarantine-aware`**").foregroundColor(.black)
                }
            }.padding(5.0)
        }.background(
            RoundedRectangle(cornerSize: .init(width: 5.0, height: 5.0)).fill(Color(cgColor: .init(red: 58/255.0, green: 194/255.0, blue: 72/255.0, alpha: 1.0)))
        ).help(helpText)
    }
}

struct GroupLeaderView: View {
    var body: some View {
        Group {
            HStack {
                Image(systemName: "arrow.up.and.down.square").symbolRenderingMode(.palette).foregroundColor(.black).font(Font.system(size: 15, weight: .bold))
                Text("**`Group leader`**").foregroundColor(.black)
            }
            .padding(5.0)
        }.background(
            RoundedRectangle(cornerSize: .init(width: 5.0, height: 5.0)).fill(helpfulProcessColor)
        ).help("This process is the leader of its group.")
    }
}

// MARK: Parent proc event view
struct ParentProcessMetadata: View {
    var selectedMessage: ESMessage
    var isExpanded: Bool
    
    var body: some View {
        ScrollView(.horizontal) {
            FactRow {
                Fact("Process name", selectedMessage.process.executable?.name ?? "")
                if let parentSigningID = selectedMessage.process.signing_id.nonEmpty {
                    Fact("Signing ID", parentSigningID)
                }
                if selectedMessage.process.file_quarantine_type != "DISABLED" {
                    FileQuarantineLabelView(type: selectedMessage.process.file_quarantine_type)
                }
            }
        }
        
        
        if isExpanded {
            let path = selectedMessage.process.executable?.path ?? ""
            FactRow(name: "Process path", value: path)
                .help(path)
        }
    }
}

// MARK: - Message details
/// An event's message details, atop the Metadata and Parent tabs: when it happened, its message version and the
/// thread it came from, then anything the tab adds in the same box.
struct MessageDetailsHeader<Content: View>: View {
    /// The event.
    let message: ESMessage
    /// What the tab adds below the message's facts.
    @ViewBuilder let content: () -> Content

    var body: some View {
        Label("**Message details**", systemImage: "envelope.badge.shield.half.filled")
            .font(.title2)

        GroupBox {
            FactRow {
                Label("**Message timestamp:**", systemImage: "clock")
                EventTimeView(message: message)
            }
            FactRow {
                Fact("Version", String(message.version), systemImage: "number")
                Fact("Thread ID", message.thread.map { String($0.thread_id) } ?? "None", systemImage: "scribble")
            }

            content()
        }
    }
}

// MARK: - Event View
/// Event Facts' Metadata tab: the message's details, the process that caused the event, and what the event says.
struct SystemTargetProcessView: View {
    var selectedMessage: ESMessage
    @State private var parentProcessExpanded: Bool = false

    var body: some View {
        VStack(alignment: .leading) {
            MessageDetailsHeader(message: selectedMessage) {
                Divider()

                HStack {
                    Text("**Parent process**")
                        .font(.title3)

                    Button("\(parentProcessExpanded ? "Hide" : "Show") parent details") {
                        parentProcessExpanded.toggle()
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                ParentProcessMetadata(
                    selectedMessage: selectedMessage,
                    isExpanded: parentProcessExpanded
                )

                if parentProcessExpanded {
                    parentDetails
                }
            }

            Divider()

            // MARK: - Event specific views
            eventMetadataView
        }.textSelection(.enabled)
    }

    /// The parent process's code signing type, age, user, PID and group ID, and its Unix and launched-by parents.
    @ViewBuilder
    private var parentDetails: some View {
        let process = selectedMessage.process
        VStack(alignment: .leading) {
            FactRow {
                Fact("Code signing type", process.codeSigningTypeLabel(version: selectedMessage.version))
                /// The process row may be shared: its age is the event's, as the Parent tab reads it.
                if let age = selectedMessage.processAgeText {
                    Fact("Parent process age", age)
                }
            }
            /// The PID and group ID of the process that caused the event. For an exec that's the process that called
            /// exec, as the Parent tab's Parent PID is: its own Unix parent is in ``ParentsView``.
            FactRow {
                Label("**Parent user:**", systemImage: "person.fill")
                /// As wide as the user, so the PID and group ID follow it.
                UserFact(process: process).fixedSize()
                Fact("PID", String(process.pid))
                Fact("GID", String(process.group_id))
            }

            // MARK: Parents
            ParentsView(message: selectedMessage)
        }
    }
}
