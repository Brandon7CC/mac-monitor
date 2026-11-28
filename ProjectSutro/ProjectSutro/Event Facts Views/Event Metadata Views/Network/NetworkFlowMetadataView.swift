//
//  NetworkFlowMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/25/26.
//

import SwiftUI
import SutroESFramework


/// What a network flow says, `new_flow` and `flow_closed` alike, row by row as ``NetworkFlowFacts`` lays it out: which
/// way it went and its protocol, the remote host, the local endpoint, the URL, the first-party site, a closed flow's
/// bytes and how long it was open, the app a delegated socket acted for, and last its identifier and when it opened.
struct NetworkFlowMetadataView: View {
    var message: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let flow = NetworkFlowFacts(message: message) {
            EventFactsCard(message: message) {
                FactsBox {
                    ForEach(Array(flow.rows.enumerated()), id: \.offset) { _, row in
                        FactRow(stacked: row.contains(where: \.isLong)) {
                            ForEach(row) { EventFactView(fact: $0) }
                        }
                    }
                }
            }
        }
    }
}
