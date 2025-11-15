//
//  EventChartViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import Charts
import SutroESFramework

struct SystemChartEventView: View {
    @State private var chartPropertiesShow: Bool = false
    var systemEventsInScope: [ESMessage]

    let orderedEventTypes: [String] = [
        "EXEC",
        "FORK",
        "EXIT",
        "MMAP",
        "MPROTECT",
        "CREATE",
        "DELETEEXTATTR",
        "SETEXTATTR",
        "LAUNCH_ITEM_ADD",
        "LAUNCH_ITEM_REMOVE",
        "OPENSSH_LOGIN",
        "OPENSSH_LOGOUT",
        "MOUNT",
        "LOGIN_LOGIN",
        "DUP",
        "RENAME",
        "LW_UNLOCK",
        "LW_LOGIN",
        "XP_MALWARE_DETECTED",
        "XP_MALWARE_REMEDIATED",
        "UNLINK",
        "OPEN",
        "WRITE",
        "LINK",
        "CLOSE",
        "SIGNAL",
        "REMOTE_THREAD",
        "IOKIT_OPEN",
        "CS_INVALIDATED",
        "PROC_SUSPEND_RESUME",
        "TRACE",
        "GET_TASK",
        "PROC_CHECK",
        "PROFILE_ADD",
        "OD_CREATE_USER",
        "OD_MODIFY_PASSWORD",
        "OD_GROUP_ADD",
        "OD_GROUP_CREATE",
        "OD_GROUP_REMOVE",
        "OD_ATTR_ADD",
        "XPC_CONNECT",
        "AUTH_PETITION",
        "AUTH_JUDGEMENT",
        "TCC_MODIFY",
        "GATEKEEPER_USER_OVERRIDE",
        "SETMODE",
        "PTY_GRANT",
        "UIPC_CONNECT",
        "UIPC_BIND"
    ]

    private func eventCounts() -> [String: Int] {
        return systemEventsInScope.reduce(into: [:]) {
 counts,
 message in
            if message.event.exec != nil { counts["EXEC", default: 0] += 1 }
            if message.event.fork != nil { counts["FORK", default: 0] += 1 }
            if message.event.exit != nil { counts["EXIT", default: 0] += 1 }
            if message.event.mmap != nil { counts["MMAP", default: 0] += 1 }
            if message.event.mprotect != nil { counts["MPROTECT", default: 0] += 1 }
            if message.event.create != nil { counts["CREATE", default: 0] += 1 }
            if message.event.deleteextattr != nil {
                counts["DELETEEXTATTR", default: 0] += 1
            }
            if message.event.setextattr != nil {
                counts["SETEXTATTR", default: 0] += 1
            }
            if message.event.btm_launch_item_add != nil {
                counts["LAUNCH_ITEM_ADD", default: 0] += 1
            }
            if message.event.btm_launch_item_remove != nil {
                counts["LAUNCH_ITEM_REMOVE", default: 0] += 1
            }
            if message.event.openssh_login != nil {
                counts["OPENSSH_LOGIN", default: 0] += 1
            }
            if message.event.openssh_logout != nil {
                counts["OPENSSH_LOGOUT", default: 0] += 1
            }
            if message.event.mount != nil { counts["MOUNT", default: 0] += 1 }
            if message.event.login_login != nil {
                counts["LOGIN_LOGIN", default: 0] += 1
            }
            if message.event.dup != nil { counts["DUP", default: 0] += 1 }
            if message.event.rename != nil { counts["RENAME", default: 0] += 1 }
            if message.event.lw_session_unlock != nil {
                counts["LW_UNLOCK", default: 0] += 1
            }
            if message.event.lw_session_login != nil {
                counts["LW_LOGIN", default: 0] += 1
            }
            if message.event.xp_malware_detected != nil {
                counts["XP_MALWARE_DETECTED", default: 0] += 1
            }
            if message.event.xp_malware_remediated != nil {
                counts["XP_MALWARE_REMEDIATED", default: 0] += 1
            }
            if message.event.unlink != nil { counts["UNLINK", default: 0] += 1 }
            if message.event.open != nil { counts["OPEN", default: 0] += 1 }
            if message.event.write != nil { counts["WRITE", default: 0] += 1 }
            if message.event.link != nil { counts["LINK", default: 0] += 1 }
            if message.event.close != nil { counts["CLOSE", default: 0] += 1 }
            if message.event.signal != nil { counts["SIGNAL", default: 0] += 1 }
            if message.event.remote_thread_create != nil {
                counts["REMOTE_THREAD", default: 0] += 1
            }
            if message.event.iokit_open != nil {
                counts["IOKIT_OPEN", default: 0] += 1
            }
            if message.event.cs_invalidated != nil {
                counts["CS_INVALIDATED", default: 0] += 1
            }
            if message.event.proc_suspend_resume != nil {
                counts["PROC_SUSPEND_RESUME", default: 0] += 1
            }
            if message.event.trace != nil { counts["TRACE", default: 0] += 1 }
            if message.event.get_task != nil {
                counts["GET_TASK", default: 0] += 1
            }
            if message.event.proc_check != nil {
                counts["PROC_CHECK", default: 0] += 1
            }
            if message.event.profile_add != nil {
                counts["PROFILE_ADD", default: 0] += 1
            }
            if message.event.authorization_judgement != nil {
                counts["AUTH_JUDGEMENT", default: 0] += 1
            }
            if message.event.authorization_petition != nil {
                counts["AUTH_PETITION", default: 0] += 1
            }
            if message.event.od_create_user != nil {
                counts["OD_CREATE_USER", default: 0] += 1
            }
            if message.event.od_modify_password != nil {
                counts["OD_MODIFY_PASSWORD", default: 0] += 1
            }
            
            if message.event.od_group_add != nil {
                counts["OD_GROUP_ADD", default: 0] += 1
            }
            if message.event.od_create_group != nil {
                counts["OD_GROUP_CREATE", default: 0] += 1
            }
            if message.event.od_group_remove != nil {
                counts["OD_GROUP_REMOVE", default: 0] += 1
            }
            if message.event.od_attribute_value_add != nil {
                counts["OD_ATTR_ADD", default: 0] += 1
            }
            
            if message.event.xpc_connect != nil {
                counts["XPC_CONNECT", default: 0] += 1
            }
            
            if message.event.uipc_connect != nil {
                counts["UIPC_CONNECT", default: 0] += 1
            }
            
            if message.event.uipc_bind != nil {
                counts["UIPC_BIND", default: 0] += 1
            }
            
            if message.event.tcc_modify != nil {
                counts["TCC_MODIFY", default: 0] += 1
            }
            
            if message.event.gatekeeper_user_override != nil {
                counts["GATEKEEPER_USER_OVERRIDE", default: 0] += 1
            }
            
            if message.event.setmode != nil {
                counts["SETMODE", default: 0] += 1
            }
            
            if message.event.pty_grant != nil {
                counts["PTY_GRANT", default: 0] += 1
            }
        }
    }

    private func esEventFrequency(for counts: [String: Int]) -> [(eventType: String, frequency: Int)] {
        return orderedEventTypes.compactMap { eventType in
            guard let frequency = counts[eventType], frequency > 0 else {
                return nil
            }
            return (eventType: eventType, frequency: frequency)
        }
    }

    var body: some View {
        let counts = eventCounts()
        let eventFrequency = esEventFrequency(for: counts)
        VStack {
            if !systemEventsInScope.isEmpty {
                Chart {
                    ForEach(eventFrequency, id: \.eventType) { esEvent in
                        BarMark(
                            x: .value("Frequency", esEvent.frequency),
                            y: .value("Event Type", esEvent.eventType)
                        ).foregroundStyle(by: .value("Event type", esEvent.eventType))
                    }
                }.chartLegend(.hidden).sheet(isPresented: $chartPropertiesShow) {
                    VStack(alignment: .leading) {
                        Text("Select events to measure")
                    }
                }
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
