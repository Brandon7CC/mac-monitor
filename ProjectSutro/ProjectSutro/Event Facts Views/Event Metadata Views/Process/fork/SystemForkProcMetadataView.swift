//
//  SystemForkProcMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

// MARK: - Fork event metadata
/// What a `fork` event says: the child process.
struct SystemForkProcMetadataView: View {
    var selectedMessage: ESMessage

    @State private var showChildAuditTokens: Bool = false

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = selectedMessage.event.fork {
            EventFactsCard(message: selectedMessage) {
                ProcessView(message: selectedMessage, process: event.child, ageText: event.childAgeText)
            } context: {
                Button("**Child audit tokens**") {
                    showChildAuditTokens.toggle()
                }
            }.sheet(isPresented: $showChildAuditTokens) {
                AuditTokenView(process: event.child)
                Button("**Dismiss**") {
                    showChildAuditTokens.toggle()
                }.padding(.bottom)
            }
        }
    }
}
