//
//  SystemListExtattrMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/21/25.
//

import SwiftUI
import SutroESFramework


/// What a `listextattr` event says: the file whose extended attributes were listed.
struct SystemListExtattrMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.listextattr {
            EventFactsCard(message: esSystemEvent) {
                ExtendedAttributeFacts(file: event.target)
            }
        }
    }
}
