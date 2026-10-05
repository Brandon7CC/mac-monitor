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
    
    var body: some View {
        OpenDirectoryFactsView(message: esSystemEvent, event: event, role: "removing a member from the group") {
            OrangeEventLabelView(message: esSystemEvent)
        } facts: {
            OpenDirectoryGroupMemberFacts(event: event)
        }
    }
}
