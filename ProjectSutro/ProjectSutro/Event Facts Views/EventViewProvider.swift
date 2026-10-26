//
//  EventViewProvider.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/5/25.
//

import Foundation
import SwiftUI
import SutroESFramework


extension SystemTargetProcessView {
    /// The facts only an event of its type has (an exec's target, a rename's source and destination, and so on), or
    /// an empty view for an event without one. `AnyView` keeps 51 branches out of the view's type.
    var eventMetadataView: AnyView {
        let message = selectedMessage, event = selectedMessage.event
        switch message {
        // MARK: - Process events
        case _ where event.exec != nil:
            return AnyView(SystemTargetExecProcMetadataView(selectedMessage: message))
        case _ where event.fork != nil:
            return AnyView(SystemForkProcMetadataView(selectedMessage: message))
        case _ where event.exit != nil:
            return AnyView(SystemProcExitMetadataView(esSystemEvent: message))
        case _ where event.signal != nil:
            return AnyView(SystemProcessSignalMetadataView(esSystemEvent: message))
        case _ where event.proc_suspend_resume != nil:
            return AnyView(SystemProcessSocketMetadataView(esSystemEvent: message))
        case _ where event.proc_check != nil:
            return AnyView(SystemProcessCheckMetadataView(esSystemEvent: message))

        // MARK: - Interprocess events
        case _ where event.remote_thread_create != nil:
            return AnyView(SystemRemoteThreadCreateMetadataView(esSystemEvent: message))
        case _ where event.trace != nil:
            return AnyView(SystemProcessTraceMetadataView(esSystemEvent: message))

        // MARK: - Code Signing events
        case _ where event.cs_invalidated != nil:
            return AnyView(SystemCodeSigningInvalidatedMetadataView(esSystemEvent: message))

        // MARK: - Memory mapping events
        case _ where event.mmap != nil:
            return AnyView(SystemMMAPMetadataView(esSystemEvent: message))
        case _ where event.mprotect != nil:
            return AnyView(SystemMProtectMetadataView(esSystemEvent: message))

        // MARK: - File System events
        case _ where event.create != nil:
            return AnyView(SystemFileCreateMetadataView(esSystemEvent: message))
        case _ where event.rename != nil:
            return AnyView(SystemFileRenameMetadataView(esSystemEvent: message))
        case _ where event.open != nil:
            return AnyView(SystemFileOpenMetadataView(esSystemEvent: message))
        case _ where event.write != nil:
            return AnyView(SystemFileWriteMetadataView(esSystemEvent: message))
        case _ where event.close != nil:
            return AnyView(SystemFileCloseMetadataView(esSystemEvent: message))
        case _ where event.unlink != nil:
            return AnyView(SystemUnlinkEventMetadataView(esSystemEvent: message))
        case _ where event.dup != nil:
            return AnyView(SystemFDDuplicateMetadataView(esSystemEvent: message))

        // MARK: - Symbolic Link events
        case _ where event.link != nil:
            return AnyView(SystemLinkEventMetadataView(esSystemEvent: message))

        // MARK: - File Metadata events
        case _ where event.setextattr != nil:
            return AnyView(SystemSetXattrMetadataView(esSystemEvent: message))
        case _ where event.getextattr != nil:
            return AnyView(SystemGetXattrMetadataView(esSystemEvent: message))
        case _ where event.deleteextattr != nil:
            return AnyView(SystemDeleteXattrMetadataView(esSystemEvent: message))
        case _ where event.listextattr != nil:
            return AnyView(SystemListExtattrMetadataView(esSystemEvent: message))
        case _ where event.setmode != nil:
            return AnyView(SystemSetModeMetadataView(esSystemEvent: message))

        // MARK: - Pseudoterminal events
        case _ where event.pty_grant != nil:
            return AnyView(SystemPTYGrantMetadataView(esSystemEvent: message))

        // MARK: - Service Management events
        case _ where event.btm_launch_item_add != nil:
            return AnyView(SystemBTMAddMetadataView(esSystemEvent: message))
        case _ where event.btm_launch_item_remove != nil:
            return AnyView(SystemBTMRemoveMetadataView(esSystemEvent: message))

        // MARK: OpenSSH events
        case _ where event.openssh_login != nil:
            return AnyView(SystemOpenSSHLoginMetadataView(esSystemEvent: message))
        case _ where event.openssh_logout != nil:
            return AnyView(SystemOpenSSHLogoutMetadataView(esSystemEvent: message))

        // MARK: - XProtect events
        case _ where event.xp_malware_detected != nil:
            return AnyView(SystemXProtectDetectMetadataView(esSystemEvent: message))
        case _ where event.xp_malware_remediated != nil:
            return AnyView(SystemXProtectRemediateMetadataView(esSystemEvent: message))

        // MARK: - File System Mounting events
        case _ where event.mount != nil:
            return AnyView(SystemMountMetadataView(esSystemEvent: message))

        // MARK: Login events
        case _ where event.login_login != nil:
            return AnyView(SystemLoginLoginMetadataView(esSystemEvent: message))
        case _ where event.lw_session_login != nil:
            return AnyView(SystemLWLoginMetadataView(esSystemEvent: message))
        case _ where event.lw_session_unlock != nil:
            return AnyView(SystemLWUnlockMetadataView(esSystemEvent: message))

        // MARK: Kernel events
        case _ where event.iokit_open != nil:
            return AnyView(SystemIOKitOpenMetadataView(esSystemEvent: message))

        // MARK: - Task Port events
        case _ where event.get_task != nil:
            return AnyView(SystemGetTaskMetadataView(esSystemEvent: message))

        // MARK: MDM events
        case _ where event.profile_add != nil:
            return AnyView(SystemProfileAddMetadataView(esSystemEvent: message))

        // MARK: - Security Authorization events
        case _ where event.authorization_judgement != nil:
            return AnyView(SystemAuthorizationJudgementMetadataView(esSystemEvent: message))
        case _ where event.authorization_petition != nil:
            return AnyView(SystemAuthorizationPetitionMetadataView(esSystemEvent: message))

        // MARK: - XPC events
        case _ where event.xpc_connect != nil:
            return AnyView(SystemXPCConnectMetadataView(esSystemEvent: message))

        // MARK: - Open Directory events
        case _ where event.od_create_user != nil:
            return AnyView(SystemOpenDirectoryCreateUserMetadataView(esSystemEvent: message))
        case _ where event.od_modify_password != nil:
            return AnyView(SystemOpenDirectoryModifyPasswordMetadataView(esSystemEvent: message))
        case _ where event.od_group_add != nil:
            return AnyView(SystemOpenDirectoryGroupAddMetadataView(esSystemEvent: message))
        case _ where event.od_group_remove != nil:
            return AnyView(SystemOpenDirectoryGroupRemoveMetadataView(esSystemEvent: message))
        case _ where event.od_create_group != nil:
            return AnyView(SystemOpenDirectoryCreateGroupMetadataView(esSystemEvent: message))
        case _ where event.od_attribute_value_add != nil:
            return AnyView(SystemOpenDirectoryAttrAddMetadataView(esSystemEvent: message))

        // MARK: - Socket events
        case _ where event.uipc_connect != nil:
            return AnyView(SystemUIPCConnectMetadataView(message: message))
        case _ where event.uipc_bind != nil:
            return AnyView(SystemUIPCBindMetadataView(message: message))

        // MARK: - TCC events
        case _ where event.tcc_modify != nil:
            return AnyView(SystemTCCModifyMetadataView(message: message))

        // MARK: - Gatekeeper events
        case _ where event.gatekeeper_user_override != nil:
            return AnyView(SystemGatekeeperUserOverrideMetadataView(message: message))

        default:
            return AnyView(EmptyView())
        }
    }
}
