//
//  SystemForkProcMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

// MARK: - Fork event metadata
/// What a `fork` event says: the child process. Its audit tokens are in the card's Details box.
struct SystemForkProcMetadataView: View {
    var selectedMessage: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = selectedMessage.event.fork {
            EventFactsCard(message: selectedMessage, target: event.child) {
                ProcessView(message: selectedMessage, process: event.child, ageText: event.childAgeText)
            }
        }
    }
}
