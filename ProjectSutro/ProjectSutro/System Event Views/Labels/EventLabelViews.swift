//
//  EventLabelViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework


struct ExecEventLabelView: View {
    var message: ESMessage
    
    private var event: ESProcessExecEvent {
        message.event.exec!
    }
    
    private var procPath: String {
        event.target.executable?.path ?? ""
    }
    
    var body: some View {
        HStack {
            // MARK: Dyld Exec Path
            if event.dyld_exec_path != nil && event.dyld_exec_path != procPath {
                Image(systemName: "curlybraces.square").help("Dyld exec path does not match the process path.")
            }
            
            // MARK: DYLD_INSERT_LIBRARIES
            if event.env
                .joined().lowercased()
                .contains("dyld_insert_libraries") {
                Image(systemName: "bookmark.slash").help("Dyld injection attempt.").symbolRenderingMode(.palette).foregroundStyle(.red)
            }
            
            // MARK: File Quarantine-aware
            if event.target.file_quarantine_type != .disabled {
                Image(systemName: "lock.icloud").symbolRenderingMode(.multicolor)
                    .padding([.leading], 2.0)
                    .help("Target is File Quarantine-aware.")
            }
            
            // MARK: ADHOC
            if event.target.is_adhoc_signed {
                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow)
                Label("**`\(message.es_event_type)`**", systemImage: "xmark.seal").symbolRenderingMode(.palette).foregroundStyle(.orange)
            } else if event.target.signing_id != nil && event.target.signing_id! != "Unknown" {
                // MARK: Signed
                Label("**`\(message.es_event_type)`**", systemImage: "checkmark.seal")
            } else {
                // MARK: Unsigned
                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .red)
                Label("**`\(message.es_event_type)`**", systemImage: "xmark.seal").symbolRenderingMode(.palette).foregroundStyle(.red)
            }
        }.frame(alignment: .leading)
    }
}


struct ForkEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        Label(
            "**`\(message.es_event_type)`**",
            systemImage: "point.topleft.down.curvedto.point.bottomright.up"
        )
    }
}

struct FileCreateEventLabelView: View {
    var message: ESMessage
    
    private var event: ESFileCreateEvent {
        message.event.create!
    }
    
    var body: some View {
        let destinationPath: String = {
            switch event.destination {
            case .new_path(let np): return "\(np.dir.path)/\(np.filename)"
            case .existing_file(let f): return f.path
            }
        }()
        HStack {
            if (message.process.file_quarantine_type != .disabled || (message.process.executable?.name == "ArchiveService" && !destinationPath.hasPrefix("/private/var/folders/"))) && event.is_quarantined == 0 {
                // MARK: Unquarantiened file
                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("Unquarantined file created")
                Label("**`\(message.es_event_type)`**", systemImage: "doc.plaintext").symbolRenderingMode(.palette).foregroundStyle(.red)
            } else if event.is_quarantined == 1 {
                // MARK: Quarantined file
                Image(systemName: "lock.shield").help("File is quarantined")
                Label("**`\(message.es_event_type)`**", systemImage: "doc.plaintext")
            }
            else {
                Label("**`\(message.es_event_type)`**", systemImage: "doc.plaintext")
            }
        }.frame(alignment: .leading)
    }
}

struct MMAPEventLabelView: View {
    var message: ESMessage
    
    private var event: ESMMapEvent {
        message.event.mmap!
    }
    
    var body: some View {
        let filePath: String = event.source.path
        // MARK: MMAP OSA
        if pathIsOSAComponent(filePath: filePath) {
            HStack {
                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("This file is an OSA (Open Scripting Architecture) component")
                Label("**`\(message.es_event_type)`**", systemImage: "memorychip").foregroundStyle(.orange)
            }
        } else {
            Label("**`\(message.es_event_type)`**", systemImage: "memorychip")
        }
    }
}

struct ExitEventLabelView: View {
    var message: ESMessage
    
    private var event: ESProcessExitEvent {
        message.event.exit!
    }
    
    var body: some View {
        HStack {
            // MARK: Non-zero Exit Code
            if event.stat != 0 {
                Image(systemName: "info.square").symbolRenderingMode(.palette).help("Non-zero exit code")
            }
            Label("**`\(message.es_event_type)`**", systemImage: "eject.fill")
        }
    }
}

struct DeleteXattrEventLabelView: View {
    var message: ESMessage
    
    private var event: ESXattrDeleteEvent {
        message.event.deleteextattr!
    }
    
    var body: some View {
        let xattr = event.extattr
        // MARK: Quarantine Xattr Delete
        if xattr.hasSuffix("apple.quarantine") {
            HStack {
                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("Quarantine extended attribute deleted")
                Label("**`\(message.es_event_type)`**", systemImage: "lock.slash").symbolRenderingMode(.palette).foregroundStyle(.red)
            }
        } else {
            Label("**`\(message.es_event_type)`**", systemImage: eventStringToImage(from: message.es_event_type)).foregroundStyle(.orange)
        }
    }
}

struct BTMLaunchItemAddEventLabelView: View {
    var message: ESMessage
    
    private var event: ESLaunchItemAddEvent {
        message.event.btm_launch_item_add!
    }
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("These events indicate a background task was added")
            Label("**`\(message.es_event_type)`**", systemImage: "lock.doc").symbolRenderingMode(.palette).foregroundStyle(.orange)
        }.frame(alignment: .leading)
    }
}


struct BTMLaunchItemRemoveEventLabelView: View {
    var message: ESMessage
    
    private var event: ESLaunchItemRemoveEvent {
        message.event.btm_launch_item_remove!
    }
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("These events indicate a background task was removed")
            Label("**`\(message.es_event_type)`**", systemImage: "lock.doc").symbolRenderingMode(.palette).foregroundStyle(.orange)
        }.frame(alignment: .leading)
    }
}


struct OpenSSHLabelView: View {
    var message: ESMessage
    
    var body: some View {
        HStack {
            Label("**`\(message.es_event_type)`**", systemImage: "network").symbolRenderingMode(.palette).foregroundStyle(.blue)
        }.frame(alignment: .leading)
    }
}


struct XProtectMalwareDetectedEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .purple)
            Label("**`\(message.es_event_type)`**", systemImage: "bolt.shield").symbolRenderingMode(.palette).foregroundStyle(.purple)
        }.frame(alignment: .leading)
    }
}


struct XProtectMalwareRemediatedEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .purple)
            Label("**`\(message.es_event_type)`**", systemImage: "checkmark.shield").symbolRenderingMode(.palette).foregroundStyle(.purple)
        }.frame(alignment: .leading)
    }
}

struct MountEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        Label("**`\(message.es_event_type)`**", systemImage: "mount")
    }
}

struct LoginLoginEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        Label("**`\(message.es_event_type)`**", systemImage: "person.fill.checkmark").foregroundStyle(.blue)
    }
}

struct LoginWindowLoginEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        Label("**`\(message.es_event_type)`**", systemImage: "macwindow.badge.plus").foregroundStyle(.blue)
    }
}

struct LoginWindowUnlockEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        Label("**`\(message.es_event_type)`**", systemImage: "macwindow.badge.plus").foregroundStyle(.blue)
    }
}

struct FDDuplicateEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        Label("**`\(message.es_event_type)`**", systemImage: "folder.badge.plus")
    }
}

struct FileRenameEventLabelView: View {
    var message: ESMessage
    private var event: ESFileRenameEvent { message.event.rename! }
    
    var body: some View {
        let eventType = message.es_event_type
        let config = configuration(for: event)
        
        return AnyView(
            HStack {
                if let icon = config.icon {
                    icon
                        .symbolRenderingMode(.palette)
                        .foregroundStyle(config.iconStyle)
                        .help(config.iconHelp)
                }
                Label("**`\(eventType)`**", systemImage: config.labelIcon)
                    .foregroundStyle(config.labelStyle)
            }
        )
    }
    
    private func configuration(for event: ESFileRenameEvent) -> (icon: Image?, iconStyle: Color, iconHelp: String, labelStyle: Color, labelIcon: String) {
        if event.is_quarantined == 1 {
            // MARK: Quarantined inflated file
            return (Image(systemName: "lock.shield"), .primary, "File is quarantined", .primary, "filemenu.and.cursorarrow")
        } else if event.is_quarantined == 0 && event.destination_path.hasSuffix(".app") {
            // MARK: Unquarantined app bundle
            return (Image(systemName: "hand.raised.app"), .red, "Unquarantined application bundle", .red, "filemenu.and.cursorarrow")
        } else if event.destination_path.contains("com.apple.backgroundtaskmanagement") {
            // MARK: BTM modification
            return (Image(systemName: "exclamationmark.triangle.fill"), .yellow, "Service management database modified.", .orange, "lock.doc")
        } else {
            return (nil, .primary, "", .primary, "filemenu.and.cursorarrow")
        }
    }
}


struct FileDeleteEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        Label("**`\(message.es_event_type)`**", systemImage: eventStringToImage(from: message.es_event_type))
    }
}

struct FileOpenEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        Label("**`\(message.es_event_type)`**", systemImage: eventStringToImage(from: message.es_event_type))
    }
}


struct FileWriteEventLabelView: View {
    var message: ESMessage
    
    private var event: ESFileWriteEvent {
        message.event.write!
    }
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        HStack {
            if event.target.path.contains("backgroundtaskmanagementd") {
                // MARK: Login Item
                Image(systemName: "exclamationmark.triangle.fill")
                    .symbolRenderingMode(.palette)
                    .foregroundStyle(.black, .yellow)
                    .help("A Login Item was potentially added")
                Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
                    .foregroundStyle(.orange)
            } else {
                Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
            }
        }
        
    }
}

struct FileLinkEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
    }
}

struct FileCloseEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
    }
}


struct IOKitOpenEventLabelView: View {
    var message: ESMessage
    
    private var event: ESIOKitOpenEvent {
        message.event.iokit_open!
    }
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        HStack {
            // MARK: HID Device
            if event.user_client_class.contains("IOHIDLibUserClient") {
                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("Human Interface Device (HID) attached!")
                Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType)).foregroundStyle(.orange)
            } else {
                Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
            }
        }
    }
}


struct RemoteThreadCreateEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("Remote thread created!")
            Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType)).symbolRenderingMode(.palette).foregroundStyle(.red)
        }
    }
}

struct CodeSignatureInvalidatedEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("This process has its code signature invalidated!")
            Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType)).symbolRenderingMode(.palette).foregroundStyle(.red)
        }
    }
}


struct SetXattrEventLabelView: View {
    var message: ESMessage
    
    private var event: ESXattrSetEvent {
        message.event.setextattr!
    }
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        if event.extattr == "com.apple.quarantine" {
            Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType)).symbolRenderingMode(.palette).foregroundStyle(.green)
        } else {
            Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
        }
    }
}


struct ProcessSocketEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
    }
}


struct ProcessTraceEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("Process trace occuring")
            Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType)).symbolRenderingMode(.palette).foregroundStyle(.orange)
        }
    }
}

struct GetTaskEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("Retrieving task control port!")
            Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType)).symbolRenderingMode(.palette).foregroundStyle(.orange)
        }
    }
}

struct ProcessCheckEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
    }
}

struct ProcessSignalEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
    }
}

struct ProfileAddEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
    }
}

struct OpenDirectoryCreateUserEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
            .symbolRenderingMode(.palette).foregroundStyle(.orange)
            .help("A user was added to an Open Directory node.")
    }
}

struct OpenDirectoryModifyPasswordEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
            .symbolRenderingMode(.palette).foregroundStyle(.orange)
            .help("A user's password was modified in an Open Directory node.")
    }
}


struct OrangeEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
            .symbolRenderingMode(.palette)
            .foregroundStyle(.orange)
    }
}

// MARK: Intelligent labels
struct IntelligentEventLabelView: View {
    var message: ESMessage
    var criticality: EventCriticality?
    
    private var eventType: String {
        message.es_event_type
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
            .symbolRenderingMode(.palette)
            .criticalityTint(criticality)
    }
}

// MARK: Hard coded labels
struct SystemEventTypeLabel: View {
    var message: ESMessage
    
    @ViewBuilder
    var body: some View {
        switch message {
        case _ where message.event.exec != nil:
            ExecEventLabelView(message: message)
            
        case _ where message.event.fork != nil:
            ForkEventLabelView(message: message)
            
        case _ where message.event.create != nil:
            FileCreateEventLabelView(message: message)
            
        case _ where message.event.mmap != nil && message.event.mmap?.source.path != nil:
            MMAPEventLabelView(message: message)
            
        case _ where message.event.exit != nil:
            ExitEventLabelView(message: message)
            
        case _ where message.event.deleteextattr != nil:
            DeleteXattrEventLabelView(message: message)
            
        case _ where message.event.btm_launch_item_add != nil:
            BTMLaunchItemAddEventLabelView(message: message)
            
        case _ where message.event.btm_launch_item_remove != nil:
            BTMLaunchItemRemoveEventLabelView(message: message)
            
        case _ where message.event.openssh_login != nil || message.event.openssh_logout != nil:
            OpenSSHLabelView(message: message)
            
        case _ where message.event.xp_malware_detected != nil:
            XProtectMalwareDetectedEventLabelView(message: message)
            
        case _ where message.event.xp_malware_remediated != nil:
            XProtectMalwareRemediatedEventLabelView(message: message)
            
        case _ where message.event.mount != nil:
            MountEventLabelView(message: message)
            
        case _ where message.event.login_login != nil:
            LoginLoginEventLabelView(message: message)
            
        case _ where message.event.lw_session_login != nil:
            LoginWindowLoginEventLabelView(message: message)
            
        case _ where message.event.lw_session_unlock != nil:
            LoginWindowUnlockEventLabelView(message: message)
            
        case _ where message.event.dup != nil:
            FDDuplicateEventLabelView(message: message)
            
        case _ where message.event.rename != nil:
            FileRenameEventLabelView(message: message)
            
        case _ where message.event.unlink != nil:
            FileDeleteEventLabelView(message: message)
            
        case _ where message.event.open != nil:
            FileOpenEventLabelView(message: message)
            
        case _ where message.event.write != nil:
            FileWriteEventLabelView(message: message)
            
        case _ where message.event.link != nil:
            FileLinkEventLabelView(message: message)
            
        case _ where message.event.close != nil:
            FileCloseEventLabelView(message: message)
            
        case _ where message.event.signal != nil:
            ProcessSignalEventLabelView(message: message)
            
        case _ where message.event.iokit_open != nil:
            IOKitOpenEventLabelView(message: message)
            
        case _ where message.event.remote_thread_create != nil:
            RemoteThreadCreateEventLabelView(message: message)
            
        case _ where message.event.cs_invalidated != nil:
            CodeSignatureInvalidatedEventLabelView(message: message)
            
        case _ where message.event.setextattr != nil:
            SetXattrEventLabelView(message: message)
            
        case _ where message.event.proc_suspend_resume != nil:
            ProcessSocketEventLabelView(message: message)
            
        case _ where message.event.trace != nil:
            ProcessTraceEventLabelView(message: message)
            
        case _ where message.event.get_task != nil:
            GetTaskEventLabelView(message: message)
            
        case _ where message.event.proc_check != nil:
            ProcessCheckEventLabelView(message: message)
            
        case _ where message.event.profile_add != nil:
            ProfileAddEventLabelView(message: message)
            
        case _ where message.event.od_create_user != nil:
            OpenDirectoryCreateUserEventLabelView(message: message)
            
        case _ where message.event.od_modify_password != nil:
            OpenDirectoryModifyPasswordEventLabelView(message: message)
            
        case _ where message.event.od_group_add != nil ||
            message.event.od_group_remove != nil ||
            message.event.od_create_group != nil ||
            message.event.od_attribute_value_add != nil ||
            message.event.authorization_petition != nil ||
            message.event.authorization_judgement != nil:
            IntelligentEventLabelView(message: message, criticality: .medium)
            
        case _ where message.event.tcc_modify != nil:
            IntelligentEventLabelView(message: message, criticality: .medium)
            
        case _ where message.event.gatekeeper_user_override != nil:
            IntelligentEventLabelView(message: message, criticality: .medium)
            
        default:
            IntelligentEventLabelView(message: message)
        }
    }
}
