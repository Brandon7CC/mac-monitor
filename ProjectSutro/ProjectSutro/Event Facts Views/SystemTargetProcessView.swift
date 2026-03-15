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
/// - Launch Services
/// - Group Leader
struct AdditionalProcMetadataView: View {
    var selectedMessage: ESMessage
    
    
    var body: some View {
        if let exec = selectedMessage.event.exec {
            if selectedMessage.process.pid == 1 {
                HStack {
                    Image(systemName: "paperplane").symbolRenderingMode(.palette).foregroundColor(.black).font(Font.system(size: 15, weight: .bold))
                    Text("**`Launch Services likely`**").foregroundColor(.black)
                }.padding(5.0)
                .background(
                    RoundedRectangle(cornerSize: .init(width: 5.0, height: 5.0)).fill(helpfulProcessColor)
                ).help("This process was likely submitted by another to be run by \"Launch Services\". It's hard in this case to determine which process submitted it to run.")
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
                
                if let parentSigningID: String = selectedMessage.process.signing_id {
                    Text("\u{2022} **Signing ID:**")
                    GroupBox {
                        Text("`\(parentSigningID)`")
                    }
                }
                
                if selectedMessage.process.file_quarantine_type != .disabled {
                    FileQuarantineLabelView(
                        type: selectedMessage.process.file_quarantine_type.rawValue
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
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager

    var selectedMessage: ESMessage
    @State private var parentProcessExpanded: Bool = false
    @State private var targetMetadataExpanded: Bool = true

    private var eventViews: EventSpecificViewsProvider {
        EventSpecificViewsProvider(
            message: selectedMessage,
            systemExtensionManager: systemExtensionManager,
            allFilters: .constant(Filters())
        )
    }

    var body: some View {
        VStack(alignment: .leading) {
            Label("**Message details**", systemImage: "envelope.badge.shield.half.filled")
                .font(.title2)

            GroupBox {
                HStack {
                    Label("**Message timestamp:**", systemImage: "clock")
                    GroupBox {
                        Text("`\(selectedMessage.time)`")
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
                
                HStack {
                    Label("**Version:**", systemImage: "number")
                    GroupBox {
                        Text("`\(selectedMessage.version)`")
                    }
                    Label("**Thread ID:**", systemImage: "scribble")
                    GroupBox {
                        Text("`\(String(selectedMessage.thread.thread_id))`")
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
                                Text("\u{2022} **Code signing type:** `\(String(suffix)) (\(selectedMessage.process.cs_validation_category ?? 0))`")
                            }
                        } else {
                            Text("\u{2022} **Code signing type:** `\(selectedMessage.process.codesigning_type.rawValue)`")
                        }
                        
                        HStack {
                            Label("**Parent user:**", systemImage: "person.fill")
                            InitiatingUserView(selectedMessage: selectedMessage)
                            
                            // Parent PID / GID
                            InitiatingPIDandGIDView(selectedMessage: selectedMessage)
                                .frame(alignment: .leading)
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                    
                }
                
            }
            
            Divider()

            // MARK: - Event specific views
            eventViews.metadataView
        }.textSelection(.enabled)
    }
}

//
//struct SystemTargetProcessView: View {
//    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
//    var selectedMessage: ESMessage
//    @State private var targetMetadataExpanded: Bool = true
//    
//    var body: some View {
//        VStack(alignment: .leading) {
//            Label("**Endpoint Security message details**", systemImage: "envelope.badge.shield.half.filled").font(.title2).padding([.leading, .top], 5.0)
//            GroupBox {
//                // @note shown for all events
//                ScrollView(.horizontal) {
//                    HStack {
//                        Text("\u{2022} **Event type:**").font(.title3)
//                        GroupBox {
//                            SystemEventTypeLabel(message: selectedMessage).font(.title3)
//                        }
//                        
//                        AdditionalProcMetadataView(
//                            selectedMessage: selectedMessage
//                        )
//                        
//                        if let exec = selectedMessage.event.exec {
//                            if exec.group_id == exec.pid {
//                                GroupLeaderView()
//                            }
//                        }
//                        
//                        
//                    }.frame(maxWidth: .infinity, alignment: .leading)
//                }
//                
//                HStack {
//                    Label("**Message timestamp:**", systemImage: "clock").font(.title3).padding([.leading, .top], 5.0)
//                    GroupBox {
//                        Text("`\(selectedMessage.activity_at_ts ?? "Unknown")`").font(.title3)
//                    }
//                }.frame(maxWidth: .infinity, alignment: .leading)
//                
//                if selectedMessage.event.exec == nil && selectedMessage.event.fork == nil {
//                    InitiatingPIDandGIDView(selectedMessage: selectedMessage)
//                }
//                
//                TopLevelNonProcEventData(selectedMessage: selectedMessage)
//                
//                Divider()
//                HStack {
//                    Label("**Initiating user:**", systemImage: "person.fill").font(.title3).padding([.leading, .top], 5.0)
//                    InitiatingUserView(selectedMessage: selectedMessage)
//                }.frame(maxWidth: .infinity, alignment: .leading)
//                
//            }
//            
//            Divider()
//            
//            // TODO: Add to when adding support for new ES events
//            // Insert event specific metadata starting with exec events
//            if selectedRCEvent.exec_event != nil {
//                SystemTargetExecProcMetadataView(selectedRCEvent: selectedRCEvent)
//            } else if selectedRCEvent.fork_event != nil {
//                SystemForkProcMetadataView(selectedRCEvent: selectedRCEvent)
//            } else if selectedRCEvent.file_event != nil {
//                SystemFileCreateMetadataView(esSystemEvent: selectedRCEvent)
//                    .environmentObject(systemExtensionManager)
//            } else if selectedRCEvent.exit_event != nil {
//                SystemProcExitMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.mmap_event != nil {
//                SystemMMAPMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.btm_launch_item_add_event != nil {
//                SystemBTMAddMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.btm_launch_item_remove_event != nil {
//                SystemBTMRemoveMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.delete_xattr_event != nil {
//                SystemDeleteXattrMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.openssh_login_event != nil {
//                SystemOpenSSHLoginMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.openssh_logout_event != nil {
//                SystemOpenSSHLogoutMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.xprotect_detect_event != nil {
//                SystemXProtectDetectMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.xprotect_remediate_event != nil {
//                SystemXProtectRemediateMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.mount_event != nil {
//                SystemMountMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.login_login_event != nil {
//                SystemLoginLoginMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.lw_login_event != nil {
//                SystemLWLoginMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.lw_unlock_event != nil {
//                SystemLWUnlockMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.file_rename_event != nil {
//                SystemFileRenameMetadataView(esSystemEvent: selectedRCEvent)
//                    .environmentObject(systemExtensionManager)
//            } else if selectedRCEvent.fd_duplicate_event != nil {
//                SystemFDDuplicateMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.file_delete_event != nil {
//                SystemUnlinkEventMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.file_write_event != nil {
//                SystemFileWriteMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.link_event != nil {
//                SystemLinkEventMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.file_close_event != nil {
//                SystemFileCloseMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.process_signal_event != nil {
//                SystemProcessSignalMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.remote_thread_create_event != nil {
//                SystemRemoteThreadCreateMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.iokit_open_event != nil {
//                SystemIOKitOpenMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.code_signature_invalidated_event != nil {
//                SystemCodeSigningInvalidatedMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.set_xattr_event != nil {
//                SystemSetXattrMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.process_socket_event != nil {
//                SystemProcessSocketMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.process_trace_event != nil {
//                SystemProcessTraceMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.get_task_event != nil {
//                SystemGetTaskMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.process_check_event != nil {
//                SystemProcessCheckMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.file_open_event != nil {
//                SystemFileOpenMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.profile_add_event != nil {
//                SystemProfileAddMetadataView(esSystemEvent: selectedRCEvent)                  // macOS 14+ Sonoma
//            } else if selectedRCEvent.od_create_user_event != nil {
//                SystemOpenDirectoryCreateUserMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.od_modify_password_event != nil {
//                SystemOpenDirectoryModifyPasswordMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.xpc_connect_event != nil {
//                SystemXPCConnectMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.od_group_add_event != nil {
//                SystemOpenDirectoryGroupAddMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.od_group_remove_event != nil {
//                SystemOpenDirectoryGroupRemoveMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.authorization_petition_event != nil {
//                SystemAuthorizationPetitionMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.authorization_judgement_event != nil {
//                SystemAuthorizationJudgementMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.od_create_group_event != nil {
//                SystemOpenDirectoryCreateGroupMetadataView(esSystemEvent: selectedRCEvent)
//            } else if selectedRCEvent.od_attribute_add_event != nil {
//                SystemOpenDirectoryAttrAddMetadataView(esSystemEvent: selectedRCEvent)
//            }
//        }
//    }
//}
