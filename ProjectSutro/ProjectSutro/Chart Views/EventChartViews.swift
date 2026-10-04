//
//  EventChartViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import Charts
import SutroESFramework

/// The mini-chart: one bar per event type shown in the "System Security Unified" table.
struct SystemChartEventView: View {
    @State private var chartPropertiesShow: Bool = false
    /// Filtered events per label (see ``EventChartLabels``), counted with a grouped fetch by ``EventQueryModel``.
    var counts: [String: Int]

    let orderedEventTypes: [String] = [
        "EXEC",
        "FORK",
        "EXIT",
        "MMAP",
        "MPROTECT",
        "CREATE",
        "DELETEEXTATTR",
        "SETEXTATTR",
        "GETEXTATTR",
        "LISTEXTATTR",
        "SETMODE",
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
        "PTY_GRANT",
        "UIPC_CONNECT",
        "UIPC_BIND"
    ]

    private func esEventFrequency(for counts: [String: Int]) -> [(eventType: String, frequency: Int)] {
        return orderedEventTypes.compactMap { eventType in
            guard let frequency = counts[eventType], frequency > 0 else {
                return nil
            }
            return (eventType: eventType, frequency: frequency)
        }
    }

    var body: some View {
        let eventFrequency = esEventFrequency(for: counts)
        VStack {
            if !counts.isEmpty {
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
