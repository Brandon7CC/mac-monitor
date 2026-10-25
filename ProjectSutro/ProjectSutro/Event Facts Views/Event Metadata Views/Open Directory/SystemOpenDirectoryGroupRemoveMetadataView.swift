//
//  SystemGroupRemoveMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/27/23.
//

import SwiftUI
import SutroESFramework


/// An `od_group_remove` event's facts: a member was removed from a group.
struct SystemOpenDirectoryGroupRemoveMetadataView: View {
    var esSystemEvent: ESMessage
    
    private var event: ESODGroupRemoveEvent {
        esSystemEvent.event.od_group_remove!
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.od_group_remove != nil {
            eventContent
        }
    }

    @ViewBuilder
    private var eventContent: some View {
        OpenDirectoryFactsView(message: esSystemEvent, event: event, role: "removing a member from the group") {
            OrangeEventLabelView(message: esSystemEvent)
        } facts: {
            OpenDirectoryGroupMemberFacts(event: event)
        }
    }
}
