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
    /// Filtered events per label (see ``EventChartLabels``), counted with a grouped fetch by ``EventQueryModel``.
    var counts: [String: Int]

    /// The bars' order, top to bottom: a label missing here gets no bar.
    let orderedEventTypes: [String] = [
        "EXEC", "FORK", "EXIT", "MMAP", "MPROTECT", "CREATE", "DELETEEXTATTR", "SETEXTATTR", "GETEXTATTR",
        "LISTEXTATTR", "SETMODE", "LAUNCH_ITEM_ADD", "LAUNCH_ITEM_REMOVE", "OPENSSH_LOGIN", "OPENSSH_LOGOUT", "MOUNT",
        "LOGIN_LOGIN", "DUP", "RENAME", "LW_UNLOCK", "LW_LOGIN", "XP_MALWARE_DETECTED", "XP_MALWARE_REMEDIATED",
        "UNLINK", "OPEN", "WRITE", "LINK", "CLOSE", "SIGNAL", "REMOTE_THREAD", "IOKIT_OPEN", "CS_INVALIDATED",
        "PROC_SUSPEND_RESUME", "TRACE", "GET_TASK", "PROC_CHECK", "PROFILE_ADD", "OD_CREATE_USER", "OD_MODIFY_PASSWORD",
        "OD_GROUP_ADD", "OD_GROUP_CREATE", "OD_GROUP_REMOVE", "OD_ATTR_ADD", "XPC_CONNECT", "AUTH_PETITION",
        "AUTH_JUDGEMENT", "TCC_MODIFY", "GATEKEEPER_USER_OVERRIDE", "PTY_GRANT", "UIPC_CONNECT", "UIPC_BIND"
    ]

    private func esEventFrequency(for counts: [String: Int]) -> [(eventType: String, frequency: Int)] {
        return orderedEventTypes.compactMap { eventType in
            guard let frequency = counts[eventType], frequency > 0 else {
                return nil
            }
            return (eventType: eventType, frequency: frequency)
        }
    }

    /// macOS 27's Swift Charts draws each event type's label on its band's top edge, over the bar above it, so there
    /// each bar carries its own label. macOS 13 ignores a bar's height on this axis, so it keeps the axis labels.
    private static let barsCarryLabels = ProcessInfo.processInfo.isOperatingSystemAtLeast(
        OperatingSystemVersion(majorVersion: 27, minorVersion: 0, patchVersion: 0))

    var body: some View {
        let eventFrequency = esEventFrequency(for: counts)
        VStack {
            if !counts.isEmpty {
                let chart = Chart {
                    ForEach(eventFrequency, id: \.eventType) { esEvent in
                        if Self.barsCarryLabels {
                            BarMark(
                                x: .value("Frequency", esEvent.frequency),
                                y: .value("Event Type", esEvent.eventType),
                                height: .fixed(10)
                            )
                            .foregroundStyle(by: .value("Event type", esEvent.eventType))
                            .annotation(position: .top, alignment: .leading, spacing: 2) {
                                Text(esEvent.eventType).font(.caption).foregroundStyle(.secondary)
                            }
                        } else {
                            BarMark(
                                x: .value("Frequency", esEvent.frequency),
                                y: .value("Event Type", esEvent.eventType)
                            ).foregroundStyle(by: .value("Event type", esEvent.eventType))
                        }
                    }
                }.chartLegend(.hidden)
                if Self.barsCarryLabels {
                    chart.chartYAxis { AxisMarks { AxisGridLine() } }
                } else {
                    chart
                }
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
