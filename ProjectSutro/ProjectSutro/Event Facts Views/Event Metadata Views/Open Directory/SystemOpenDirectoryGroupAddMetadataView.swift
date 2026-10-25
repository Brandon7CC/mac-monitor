//
//  SystemGroupAddMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/27/23.
//

import SwiftUI
import SutroESFramework


/// An `od_group_add` event's facts: a member was added to a group.
struct SystemOpenDirectoryGroupAddMetadataView: View {
    var esSystemEvent: ESMessage
    
    private var event: ESODGroupAddEvent {
        esSystemEvent.event.od_group_add!
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.od_group_add != nil {
            eventContent
        }
    }

    @ViewBuilder
    private var eventContent: some View {
        OpenDirectoryFactsView(message: esSystemEvent, event: event, role: "adding a member to the group") {
            OrangeEventLabelView(message: esSystemEvent)
        } facts: {
            OpenDirectoryGroupMemberFacts(event: event)
        }
    }
}
