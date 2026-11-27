//
//  KeyPathBar.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/25/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Key path bar
/// The bar above an event's record: the key path of the value at the cursor, its keys between chevrons and the last
/// in bold, and what the telemetry schema says of it (``RecordKeyPaths``), cut to fit with the whole as its help.
struct KeyPathBar: View {
    @ObservedObject var status: EditorStatus

    var body: some View {
        HStack(spacing: 4) {
            ForEach(Array(status.keyPath.enumerated()), id: \.offset) { index, key in
                if index > 0 {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 8, weight: .semibold))
                        .foregroundStyle(.tertiary)
                }
                Text(key)
                    .fontWeight(index == status.keyPath.count - 1 ? .bold : .regular)
                    .truncationMode(.middle)
            }
            .layoutPriority(1)
            Spacer(minLength: 12)
            if let summary {
                Text(summary)
                    .foregroundStyle(.secondary)
                    .truncationMode(.tail)
                    .help(summary)
            }
        }
        .font(.system(size: 11))
        .lineLimit(1)
        .padding(.horizontal, 8)
        .frame(height: 24)
        .accessibilityElement(children: .combine)
    }

    /// What the schema says of the key path, if it says anything: a network flow's record's own, whose process is a
    /// `flow_process`.
    private var summary: String? {
        guard !status.keyPath.isEmpty else { return nil }
        return RecordKeyPaths.shared.node(status.keyPath.joined(separator: "."),
                                          inNetworkRecord: status.isNetworkRecord)?.summary
    }
}
