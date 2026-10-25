//
//  SystemCreateUserEventMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/20/23.
//

import SwiftUI
import SutroESFramework


/// An `od_create_user` event's facts: a user was created.
struct SystemOpenDirectoryCreateUserMetadataView: View {
    var esSystemEvent: ESMessage
    
    private var event: ESODCreateUserEvent {
        esSystemEvent.event.od_create_user!
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.od_create_user != nil {
            eventContent
        }
    }

    @ViewBuilder
    private var eventContent: some View {
        OpenDirectoryFactsView(message: esSystemEvent, event: event, role: "creating a new user") {
            OpenDirectoryCreateUserEventLabelView(message: esSystemEvent)
        } facts: {
            FactRow(name: "User name", value: event.user_name)
        }
    }
}
