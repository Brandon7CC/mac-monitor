//
//  EventLabelViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework


// MARK: Intelligent labels
struct IntelligentEventLabelView: View {
    var message: ESMessage
    var criticality: EventCriticality?
    
    private var eventType: String {
        message.es_event_type ?? "UNKNOWN"
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
