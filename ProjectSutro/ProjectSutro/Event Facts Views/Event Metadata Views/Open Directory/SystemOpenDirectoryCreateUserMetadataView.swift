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
    
    var body: some View {
        OpenDirectoryFactsView(message: esSystemEvent, event: event, role: "creating a new user") {
            OpenDirectoryCreateUserEventLabelView(message: esSystemEvent)
        } facts: {
            FactRow(name: "User name", value: event.user_name)
        }
    }
}
