//
//  SystemCodeSigningInvalidatedMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/4/23.
//

import SwiftUI
import SutroESFramework

/// What a `cs_invalidated` event says: nothing beyond its process, whose code signature became invalid.
struct SystemCodeSigningInvalidatedMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.cs_invalidated != nil {
            EventFactsCard(message: esSystemEvent) {
                EmptyView()
            }
        }
    }
}
