//
//  EventViewProvider.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/5/25.
//

import SwiftUI
import EndpointSecurity
import SutroESFramework


extension SystemTargetProcessView {
    /// The facts only an event of its type has (an exec's target, a rename's source and destination, and so on), or
    /// an empty view for an event without one, picked by the stored `event_type`.
    @ViewBuilder
    var eventMetadataView: some View {
        let message = selectedMessage
        switch es_event_type_t(rawValue: UInt32(truncatingIfNeeded: message.event_type)) {
        // MARK: - Process events
        case ES_EVENT_TYPE_NOTIFY_EXEC: SystemTargetExecProcMetadataView(selectedMessage: message)
        case ES_EVENT_TYPE_NOTIFY_FORK: SystemForkProcMetadataView(selectedMessage: message)
        case ES_EVENT_TYPE_NOTIFY_EXIT: SystemProcExitMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_SIGNAL: SystemProcessSignalMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME: SystemProcessSocketMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_PROC_CHECK: SystemProcessCheckMetadataView(esSystemEvent: message)

        // MARK: - Interprocess events
        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE: SystemRemoteThreadCreateMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_TRACE: SystemProcessTraceMetadataView(esSystemEvent: message)

        // MARK: - Code Signing events
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED: SystemCodeSigningInvalidatedMetadataView(esSystemEvent: message)

        // MARK: - Memory mapping events
        case ES_EVENT_TYPE_NOTIFY_MMAP: SystemMMAPMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_MPROTECT: SystemMProtectMetadataView(esSystemEvent: message)

        // MARK: - File System events
        case ES_EVENT_TYPE_NOTIFY_CREATE: SystemFileCreateMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_RENAME: SystemFileRenameMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_OPEN: SystemFileOpenMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_WRITE: SystemFileWriteMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_CLOSE: SystemFileCloseMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_UNLINK: SystemUnlinkEventMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_DUP: SystemFDDuplicateMetadataView(esSystemEvent: message)

        // MARK: - Symbolic Link events
        case ES_EVENT_TYPE_NOTIFY_LINK: SystemLinkEventMetadataView(esSystemEvent: message)

        // MARK: - File Metadata events
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR: SystemSetXattrMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_GETEXTATTR: SystemGetXattrMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR: SystemDeleteXattrMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR: SystemListExtattrMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_SETMODE: SystemSetModeMetadataView(esSystemEvent: message)

        // MARK: - Pseudoterminal events
        case ES_EVENT_TYPE_NOTIFY_PTY_GRANT: SystemPTYGrantMetadataView(esSystemEvent: message)

        // MARK: - Service Management events
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD: SystemBTMAddMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE: SystemBTMRemoveMetadataView(esSystemEvent: message)

        // MARK: OpenSSH events
        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN: SystemOpenSSHLoginMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT: SystemOpenSSHLogoutMetadataView(esSystemEvent: message)

        // MARK: - XProtect events
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED: SystemXProtectDetectMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED: SystemXProtectRemediateMetadataView(esSystemEvent: message)

        // MARK: - File System Mounting events
        case ES_EVENT_TYPE_NOTIFY_MOUNT: SystemMountMetadataView(esSystemEvent: message)

        // MARK: Login events
        case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN: SystemLoginLoginMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN: SystemLWLoginMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK: SystemLWUnlockMetadataView(esSystemEvent: message)

        // MARK: Kernel events
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN: SystemIOKitOpenMetadataView(esSystemEvent: message)

        // MARK: - Task Port events
        case ES_EVENT_TYPE_NOTIFY_GET_TASK: SystemGetTaskMetadataView(esSystemEvent: message)

        // MARK: MDM events
        case ES_EVENT_TYPE_NOTIFY_PROFILE_ADD: SystemProfileAddMetadataView(esSystemEvent: message)

        // MARK: - Security Authorization events
        case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT:
            SystemAuthorizationJudgementMetadataView(esSystemEvent: message)
        case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION:
            SystemAuthorizationPetitionMetadataView(esSystemEvent: message)

        // MARK: - XPC events
        case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT: SystemXPCConnectMetadataView(esSystemEvent: message)

        // MARK: - Open Directory events
        case ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER, ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD,
             ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD, ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE,
             ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP, ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD:
            SystemOpenDirectoryMetadataView(message: message)

        // MARK: - Socket events
        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT: SystemUIPCConnectMetadataView(message: message)
        case ES_EVENT_TYPE_NOTIFY_UIPC_BIND: SystemUIPCBindMetadataView(message: message)

        // MARK: - TCC events
        case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY: SystemTCCModifyMetadataView(message: message)

        // MARK: - Gatekeeper events
        case ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE: SystemGatekeeperUserOverrideMetadataView(message: message)

        default: EmptyView()
        }
    }
}
