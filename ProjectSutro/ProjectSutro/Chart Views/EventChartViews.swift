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

    /// Whether the axis is logarithmic, with 0 at the origin: from macOS 13.3. Before it the axis stays linear.
    private static var isLogarithmic: Bool {
        if #available(macOS 13.3, *) { return true }
        return false
    }

    /// The axis's scale: ``isLogarithmic``'s.
    private static var scale: ScaleType {
        if #available(macOS 13.3, *) { return .symmetricLog }
        return .linear
    }

    /// The share of the plot the largest bar takes, leaving the rest for its label and count.
    private static let largestBarShare = 0.6

    /// The axis's upper bound, past the largest count, so the largest bar's label and count fit beside it. On a log
    /// scale a bar's length grows with the count's logarithm, so the bound is the count raised to `1 / share`. On a
    /// linear one it's the count divided by the share.
    ///
    /// - Parameter largest: The largest count.
    /// - Returns: The bound.
    private static func upperBound(for largest: Int) -> Double {
        isLogarithmic ? max(10, pow(Double(largest) + 1, 1 / largestBarShare)) : Double(largest) / largestBarShare
    }

    /// A logarithmic axis's ticks: 0, then each power of ten up to the largest count. A linear axis uses Charts' own.
    ///
    /// - Parameter largest: The largest count.
    /// - Returns: The ticks.
    private static func ticks(upTo largest: Int) -> [Double] {
        [0] + sequence(first: 1) { $0 <= largest / 10 ? $0 * 10 : nil }.map(Double.init)
    }

    /// One type's label: its name, then its count, shortened as 30.1K.
    ///
    /// - Parameter event: The type and its count.
    /// - Returns: The label.
    private static func label(_ event: (eventType: String, frequency: Int)) -> Text {
        Text(event.eventType + " ")
            + Text(event.frequency.formatted(.number.notation(.compactName))).foregroundColor(.secondary)
    }

    /// One bar per type, on a log scale, so a type with thousands of events (mmap, close) doesn't flatten the rest.
    /// Each bar's name and count follow it, so no label sits over another bar and every count reads exactly.
    var body: some View {
        let eventFrequency = esEventFrequency(for: counts)
        VStack {
            if let largest = eventFrequency.map(\.frequency).max() {
                Chart {
                    ForEach(eventFrequency, id: \.eventType) { esEvent in
                        BarMark(
                            x: .value("Events", Double(esEvent.frequency)),
                            y: .value("Event type", esEvent.eventType)
                        )
                        .foregroundStyle(by: .value("Event type", esEvent.eventType))
                        .annotation(position: .trailing, alignment: .leading, spacing: 4) {
                            Self.label(esEvent).font(.caption).lineLimit(1)
                        }
                    }
                }
                .chartLegend(.hidden)
                .chartYAxis(.hidden)
                .chartXScale(domain: 0...Self.upperBound(for: largest), type: Self.scale)
                .chartXAxis {
                    if Self.isLogarithmic {
                        AxisMarks(values: Self.ticks(upTo: largest)) { value in
                            AxisGridLine()
                            AxisValueLabel {
                                if let count = value.as(Double.self) {
                                    Text(Int(count).formatted(.number.notation(.compactName)))
                                }
                            }
                        }
                    } else {
                        AxisMarks()
                    }
                }
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
