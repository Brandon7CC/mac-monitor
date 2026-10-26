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
                LaunchedByParentBadge(parent)
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
                case "OPT-IN":
                    Text("**`File Quarantine-aware`**").foregroundColor(.black)
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

struct InitiatingPIDandGIDView: View {
    var selectedMessage: ESMessage
    
    var parentPid: Int {
        if let exec = selectedMessage.event.exec {
            return Int(exec.target.ppid)
        }
        return Int(selectedMessage.process.pid)
    }
    
    var body: some View {
        HStack {
            Text("\u{2022} **PID:**")
            GroupBox {
                Text("`\(String(parentPid))`")
            }
            Text("\u{2022} **GID:**")
            GroupBox {
                Text("`\(String(selectedMessage.process.group_id))`")
            }
        }    }
}

// MARK: Parent proc event view
struct ParentProcessMetadata: View {
    var selectedMessage: ESMessage
    var isExpanded: Bool
    
    var body: some View {
        ScrollView(.horizontal) {
            HStack {
                Text("\u{2022} **Process name:**")
                GroupBox {
                    Text("`\(String(selectedMessage.process.executable?.name ?? ""))`")
                }
                
                if let parentSigningID: String = selectedMessage.process.signing_id.nonEmpty {
                    Text("\u{2022} **Signing ID:**")
                    GroupBox {
                        Text("`\(parentSigningID)`")
                    }
                }
                
                if selectedMessage.process.file_quarantine_type != "DISABLED" {
                    FileQuarantineLabelView(
                        type: selectedMessage.process.file_quarantine_type
                    )
                }
                
                
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
        
        
        if isExpanded {
            HStack {
                Text("\u{2022} **Process path:**")
                GroupBox {
                    Text("`\(selectedMessage.process.executable?.path ?? "")`")
                        .help(selectedMessage.process.executable?.path ?? "")
                        .lineLimit(30)
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

// MARK: - Event View
struct SystemTargetProcessView: View {
    var selectedMessage: ESMessage
    @State private var parentProcessExpanded: Bool = false

    var body: some View {
        VStack(alignment: .leading) {
            Label("**Message details**", systemImage: "envelope.badge.shield.half.filled")
                .font(.title2)

            GroupBox {
                HStack {
                    Label("**Message timestamp:**", systemImage: "clock")
                    EventTimeView(message: selectedMessage)
                }.frame(maxWidth: .infinity, alignment: .leading)
                
                HStack {
                    Label("**Version:**", systemImage: "number")
                    GroupBox {
                        Text("`\(selectedMessage.version)`")
                    }
                    Label("**Thread ID:**", systemImage: "scribble")
                    GroupBox {
                        Text("`\(selectedMessage.thread.map { String($0.thread_id) } ?? "None")`")
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
                
                
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
                    VStack(alignment: .leading) {
                        if selectedMessage.version >= 10 && selectedMessage.process.cs_validation_category != 10 {
                            if let cs_validation_string = selectedMessage.process.cs_validation_category_string {
                                let suffix = cs_validation_string.trimmingPrefix("ES_CS_VALIDATION_CATEGORY_")
                                Text("\u{2022} **Code signing type:** `\(suffix) (\(selectedMessage.process.cs_validation_category))`")
                            }
                        } else {
                            Text("\u{2022} **Code signing type:** `\(selectedMessage.process.codesigning_type)`")
                        }
                        
                        HStack {
                            Label("**Parent user:**", systemImage: "person.fill")
                            InitiatingUserView(selectedMessage: selectedMessage)
                            
                            // Parent PID / GID
                            InitiatingPIDandGIDView(selectedMessage: selectedMessage)
                                .frame(alignment: .leading)
                        }.frame(maxWidth: .infinity, alignment: .leading)
                        
                        // MARK: Parents
                        ParentsView(message: selectedMessage)
                    }
                    
                }
                
            }
            
            Divider()

            // MARK: - Event specific views
            eventMetadataView
        }.textSelection(.enabled)
    }
}
