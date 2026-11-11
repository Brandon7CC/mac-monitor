//
//  SystemDeleteExtattrMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/17/25.
//

import SwiftUI
import SutroESFramework


/// What a `deleteextattr` event says: the extended attribute deleted, and the file it was on.
struct SystemDeleteXattrMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.deleteextattr {
            EventFactsCard(message: esSystemEvent) {
                ExtendedAttributeFacts(attribute: event.extattr, file: event.target)
            }
        }
    }
}
